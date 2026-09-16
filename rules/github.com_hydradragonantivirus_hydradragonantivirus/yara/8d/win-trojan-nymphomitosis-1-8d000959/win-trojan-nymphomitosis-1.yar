rule Win_Trojan_NymphoMitosis_1
{
strings:
	$a0 = { 48cd21bb4d5a74531e0633ff8cc0488ed8383d }


condition:
	$a0
}