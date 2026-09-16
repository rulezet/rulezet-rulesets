rule Win_Trojan_C_305
{
strings:
	$a0 = { 545642534720776f726d }

	$a1 = { 530074006100720074002e007600620073 }


condition:
	$a0 and $a1
}