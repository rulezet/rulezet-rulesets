rule Win_Trojan_Yeke_1
{
strings:
	$a0 = { dabf1f000eb9f203e800005d81ed1f041f03fdfc07 }


condition:
	$a0
}