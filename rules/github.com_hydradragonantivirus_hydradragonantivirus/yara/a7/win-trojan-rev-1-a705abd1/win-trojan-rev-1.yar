rule Win_Trojan_Rev_1
{
strings:
	$a0 = { e800000ac05e81ee270a8bfe980ac0b9120a0ac090fcf990ac345398aaf9e2f8 }


condition:
	$a0
}