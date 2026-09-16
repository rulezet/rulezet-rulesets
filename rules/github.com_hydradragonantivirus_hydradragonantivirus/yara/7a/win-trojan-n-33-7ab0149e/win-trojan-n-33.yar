rule Win_Trojan_N_33
{
strings:
	$a0 = { 81ed05012e803e6501b9745db91d048dbe6501ba01 }


condition:
	$a0
}