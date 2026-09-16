rule Win_Dropper_Agent_34257
{
strings:
	$a0 = { 33c0648b38488bc8f2afaf8b1f6633db66823b4d5a740881eb00000100 }


condition:
	$a0
}