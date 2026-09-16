rule Win_Trojan_Agent_35406
{
strings:
	$a0 = { 558bec83ec28294dec8005e49000108078138035549000105f291de690001031 }


condition:
	$a0
}