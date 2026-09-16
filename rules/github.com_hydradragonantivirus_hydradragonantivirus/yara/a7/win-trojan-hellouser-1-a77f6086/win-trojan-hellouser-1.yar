rule Win_Trojan_HelloUser_1
{
strings:
	$a0 = { 90e800005d81ed09018db62801568bfeb94a018b962601ac32c2c1ca03aae2f7c3 }


condition:
	$a0
}