rule Win_Trojan_IVP_22
{
strings:
	$a0 = { 8db6????bf000157a4a58d96 }


condition:
	$a0
}