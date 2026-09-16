rule Win_Trojan_SdBot_778
{
strings:
	$a0 = { 73f96520436513eacffd775b6834636b33642d006682d82d782bb006f8474723 }


condition:
	$a0
}