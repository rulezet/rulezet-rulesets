rule Win_Trojan_Uruguay_12
{
strings:
	$a0 = { 96434f5718c9eec26da952f2e74dee42d9677357eeb322cfacaead3f11509a702d6bcd882f8d95ceca50cc6d68e66d35 }


condition:
	$a0
}