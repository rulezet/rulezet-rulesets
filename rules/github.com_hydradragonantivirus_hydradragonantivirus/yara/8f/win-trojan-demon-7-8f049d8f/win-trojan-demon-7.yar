rule Win_Trojan_Demon_7
{
strings:
	$a0 = { 01030055df1d000200ffffd01300009b05000004000000d013 }


condition:
	$a0
}