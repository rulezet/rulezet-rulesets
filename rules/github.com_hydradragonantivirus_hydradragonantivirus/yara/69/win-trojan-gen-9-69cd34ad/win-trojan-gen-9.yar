rule Win_Trojan_Gen_9
{
strings:
	$a0 = { 01b914002e31144646e2f9c3e8ebffba0001b440b151cd21e8dfffc3ba4d01b44ecd217301 }


condition:
	$a0
}