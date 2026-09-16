rule Win_Trojan_Mybot_4954
{
strings:
	$a0 = { 2106977f7b899499de4ab8bbe96b2c6ab8a37a0e6be93e81e8126dce697cb104a4c5f2abfdfb93f5a8100d9a93cb566694be4feb580bf55da4cb58bccecd6742c0afef20d6e4517379462fb216e6 }


condition:
	$a0
}