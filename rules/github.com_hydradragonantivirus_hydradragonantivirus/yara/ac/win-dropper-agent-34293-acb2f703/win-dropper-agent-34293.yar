rule Win_Dropper_Agent_34293
{
strings:
	$a0 = { 5c6e73457865632e646c6c0022fd99805c[0-10]2e657865222065202d6f2b202d70 }


condition:
	$a0
}