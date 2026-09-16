rule Win_Trojan_Centenary_1
{
strings:
	$a0 = { 088905b440b1678bd783ea6790e80a004fb440b1038bd7cd21c3cd21b8023dba9e00cd2193c3 }


condition:
	$a0
}