rule Win_Trojan_Linfo_1
{
strings:
	$a0 = { 894df87e178b7df4037df88a07c0c80534218807413bce894df8 }


condition:
	$a0
}