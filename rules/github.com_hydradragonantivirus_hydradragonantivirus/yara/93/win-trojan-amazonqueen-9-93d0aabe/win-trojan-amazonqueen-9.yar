rule Win_Trojan_AmazonQueen_9
{
strings:
	$a0 = { 1fe800008bdc368b2f81ed0500444406ff86f801b4accd213c3075132e3b9ef6017d39b4aecd21b4098d968e00cd21 }


condition:
	$a0
}