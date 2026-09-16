rule Win_Trojan_Opic_1
{
strings:
	$a0 = { ffeb0690b8004ccd21e2f61e060e0e1f07e800005d81ed16008db689008bfeb94e02e80300eb6090acd0c0d0c0d0 }


condition:
	$a0
}