rule Win_Trojan_NumberoftheBeast_1
{
strings:
	$a0 = { b8003dcd21935a520e1f1e07b102b43f }


condition:
	$a0
}