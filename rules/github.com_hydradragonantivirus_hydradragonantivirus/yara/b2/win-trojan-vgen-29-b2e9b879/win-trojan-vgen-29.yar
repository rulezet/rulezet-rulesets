rule Win_Trojan_VGEN_29
{
strings:
	$a0 = { 4559b801facd16b40dcd2133ff8edfb7024fb8024acd2fb8104abb0100cd2fb30647742be8c8fff32ea4b85c028747 }


condition:
	$a0
}