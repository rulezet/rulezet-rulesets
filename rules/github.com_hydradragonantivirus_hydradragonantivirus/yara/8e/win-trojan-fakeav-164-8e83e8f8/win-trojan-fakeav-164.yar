rule Win_Trojan_FakeAV_164
{
strings:
	$a0 = { 33c9b8??20400083ec7c518bd40308495152e8????00005a595883c47c80f46a750420e47401 }


condition:
	$a0
}