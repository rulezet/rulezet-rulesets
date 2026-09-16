rule webshell_php_generic_backticks_obfuscated
{
	meta:
		description = "Generic PHP webshell which uses backticks directly on user input"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		hash = "23dc299f941d98c72bd48659cdb4673f5ba93697"
		date = "2021/01/07"

	strings:
		$s1 = /echo[\t ]*\(?`\$/ wide ascii
	
				$php_short = "<?" wide ascii
				$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket" 

		        		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
	
	condition:
		filesize < 500 and ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and $s1
}