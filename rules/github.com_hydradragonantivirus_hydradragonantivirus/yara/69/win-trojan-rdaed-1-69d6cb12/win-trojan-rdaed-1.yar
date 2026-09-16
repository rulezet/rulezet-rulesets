rule Win_Trojan_RDAED_1
{
strings:
	$a0 = { b960038bd5cd213bc17512b80042998bcacd21b440b1058d96e900cd21b801578b8e76038b96 }


condition:
	$a0
}