rule word_xml
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "Word XML file format detection"
	strings:
		$header = "<?xml"
		$str = "<?mso-application progid=\"Word.Document\"?>"
	condition:
	   $header at 0 and $str
}