rule Win_Trojan_Tsunami_2
{
strings:
	$a0 = { 7403ea51022ea4030193bf0058b8ce30ce215351171fe9730233d3b92100e983028b1700 }


condition:
	$a0
}