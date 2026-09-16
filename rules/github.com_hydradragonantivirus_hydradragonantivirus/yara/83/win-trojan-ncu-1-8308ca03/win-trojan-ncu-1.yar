rule Win_Trojan_Ncu_1
{
strings:
	$a0 = { a55f5e071f58c32ec606190100509c580d0001509d58c3 }


condition:
	$a0
}