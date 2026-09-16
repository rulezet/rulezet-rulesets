rule Win_Trojan_KPOBOCOC_1
{
strings:
	$a0 = { 81ed03018bd581c25202b41acd218bf581c64c028bfd81c74f02b90300f3a4b42acd213c017402752ac60648020090 }


condition:
	$a0
}