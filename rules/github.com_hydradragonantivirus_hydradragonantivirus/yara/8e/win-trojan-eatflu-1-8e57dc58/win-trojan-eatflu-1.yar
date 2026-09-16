rule Win_Trojan_EatFlu_1
{
strings:
	$a0 = { b8801f595be89d0c0146fc1156fe8bc6250300995052bae101b88033595be8840c0146fc11 }


condition:
	$a0
}