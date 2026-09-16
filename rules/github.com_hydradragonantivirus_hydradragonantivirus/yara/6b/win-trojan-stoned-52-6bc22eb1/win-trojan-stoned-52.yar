rule Win_Trojan_Stoned_52
{
strings:
	$a0 = { c88ec08ed8b99a01bf0500fc8a0504f2aae2f9e9 }


condition:
	$a0
}