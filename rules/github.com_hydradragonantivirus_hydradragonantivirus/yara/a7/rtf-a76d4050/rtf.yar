rule rtf
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Word RTF file format detection"
	strings:
		$header = "{\\rt"	
	condition:
	   $header at 0
}