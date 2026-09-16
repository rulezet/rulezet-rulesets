rule Win_Trojan_Loveletter_9
{
strings:
	$a0 = { 632e636f707928737973265d2d5d252d2576616c656e74696e612e766273 }


condition:
	$a0
}