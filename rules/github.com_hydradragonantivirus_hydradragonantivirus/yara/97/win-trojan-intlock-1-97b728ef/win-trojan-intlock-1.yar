rule Win_Trojan_IntLock_1
{
strings:
	$a0 = { 35cd212e891e2d012e8c062f01b83025061f8bd3cd210e1fb81325ba0301cd21ba3101cd27 }


condition:
	$a0
}