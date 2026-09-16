rule Win_Trojan_Atomic_2
{
strings:
	$a0 = { cd21c3b002ba9e00e8ecff722a93b000e8ebff5152b440b9e800ba0001cd21b0015a59e8d8ff }


condition:
	$a0
}