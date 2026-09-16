rule Win_Trojan_AntiEnter_1
{
strings:
	$a0 = { 0500b90f048db62a008bfeeb0100ac32861600aa6a0258cd17eb04b402cd1ae2ed }


condition:
	$a0
}