rule Win_Trojan_Consumed_2
{
strings:
	$a0 = { 01007415be1c01b96001eb0290008a0432061001880446e2f5 }


condition:
	$a0
}