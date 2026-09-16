rule Win_Trojan_Tibet_1
{
strings:
	$a0 = { 5833d2bb1000f7f38cdb03d881eb8c008edbeb5c2d0ba7138e0506b42cbeea089c0e56ff2ed7088816dd08fa1e }


condition:
	$a0
}