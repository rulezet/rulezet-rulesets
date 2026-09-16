rule Win_Trojan_Agent_32810
{
strings:
	$a0 = { 8b6ac2128f3c5b7a8424febcc0c4053de29fd0811a7038893b4dd9402cf78ea9dd29a366f89f775fe3e386e2b162efbef342955126c1d7cf535ce1ec2ec3658ce7 }


condition:
	$a0
}