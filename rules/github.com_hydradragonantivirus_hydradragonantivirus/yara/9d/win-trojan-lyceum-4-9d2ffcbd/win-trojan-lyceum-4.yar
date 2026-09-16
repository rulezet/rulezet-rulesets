rule Win_Trojan_Lyceum_4
{
strings:
	$a0 = { e800005efc5053b8d0afcd213dfd0a747b561e068cc048b9 }


condition:
	$a0
}