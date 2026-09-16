rule Win_Trojan_Junkie_3
{
strings:
	$a0 = { be007cfa8be68ed7fb8ec7b80202bb007eb90400ba80005653cd13e98001 }


condition:
	$a0
}