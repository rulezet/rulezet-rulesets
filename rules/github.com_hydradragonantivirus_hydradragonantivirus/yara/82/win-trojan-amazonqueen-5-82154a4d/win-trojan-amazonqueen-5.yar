rule Win_Trojan_AmazonQueen_5
{
strings:
	$a0 = { 1fe800005d81ed050006b4accd213c3075132e3b9edb01 }


condition:
	$a0
}