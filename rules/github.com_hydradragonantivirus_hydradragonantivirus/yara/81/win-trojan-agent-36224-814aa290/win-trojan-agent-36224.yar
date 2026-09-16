rule Win_Trojan_Agent_36224
{
strings:
	$a0 = { 60be007041008dbe00a0feff57eb0b908a064688074701db75078b1e83eefc11 }

	$a1 = { 526f6f74204167656e6379 }


condition:
	$a0 and $a1
}