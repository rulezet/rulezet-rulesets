rule ppt
{
	meta:
		author = "Niels Warnars"
		date = "2016/04/26"
		description = "PowerPoint 2003 file format detection"
	strings:
		$header = { D0 CF 11 E0 A1 B1 1A E1 }
		$str = "Microsoft Office PowerPoint"
	condition:
	   $header at 0 and $str
}