rule Win_Trojan_PCBB_1679_1
{
strings:
	$a0 = { b9700689e581460012005e468074fffee2f9 }


condition:
	$a0
}