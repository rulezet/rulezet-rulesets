rule Win_Trojan_Rest_1
{
strings:
	$a0 = { b906f4bfef052e000c464f75f918ae24c71b7bf3c4016c027af40f6cfde29aff7bf3b6016e0228c00008fcfbe5 }


condition:
	$a0
}