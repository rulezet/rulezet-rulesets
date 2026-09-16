rule Win_Trojan_Unnamed_5
{
strings:
	$a0 = { fafe8bae210281c5030133f6e80000e800005d8b9e1302b440cd21b801578b9e13028b8e17028b }


condition:
	$a0
}