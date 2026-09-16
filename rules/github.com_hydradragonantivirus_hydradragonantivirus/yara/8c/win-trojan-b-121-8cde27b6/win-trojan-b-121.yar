rule Win_Trojan_B_121
{
strings:
	$a0 = { 3e7da1130448a31304b106d3e0c7075001894702508ec0b85d0050b9df00f3a5cb911e07cd13 }


condition:
	$a0
}