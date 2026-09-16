rule webshell_php_includer_tiny
{
	meta:
		description = "Suspicious: Might be PHP webshell includer, check the included file"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Arnim Rupp"
		date = "2021/04/17"

	strings:
		$php_include1 = /include\(\$_(GET|POST|REQUEST)\[/ nocase wide ascii
	
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
		filesize < 100 and ( 
			(
				( 
						$php_short in (0..100) or 
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			) 
			or any of ( $php_new* ) 
		)
		and any of ( $php_include* )
}