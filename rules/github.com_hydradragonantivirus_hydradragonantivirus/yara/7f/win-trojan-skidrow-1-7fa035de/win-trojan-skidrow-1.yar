rule Win_Trojan_SkidRow_1
{
strings:
	$a0 = { 0dcd21b452cd21fc26c57712c5348cd8504050b902008b }


condition:
	$a0
}