rule Win_Trojan_Murphy_9
{
strings:
	$a0 = { 2e8b84f3f9902ea30001902e8b84f5f9 }


condition:
	$a0
}