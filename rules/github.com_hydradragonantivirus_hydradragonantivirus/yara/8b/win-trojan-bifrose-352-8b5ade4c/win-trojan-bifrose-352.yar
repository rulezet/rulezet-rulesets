rule Win_Trojan_Bifrose_352
{
strings:
	$a0 = { 60e836feffffc3900900000024 }


condition:
	$a0
}