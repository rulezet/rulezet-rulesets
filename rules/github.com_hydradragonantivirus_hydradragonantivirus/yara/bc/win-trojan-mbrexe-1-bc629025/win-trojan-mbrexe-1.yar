rule Win_Trojan_MBRExe_1
{
strings:
	$a0 = { c08ed8390684007432a11000a37000a11200a37200a184002ea3df00a18600 }


condition:
	$a0
}