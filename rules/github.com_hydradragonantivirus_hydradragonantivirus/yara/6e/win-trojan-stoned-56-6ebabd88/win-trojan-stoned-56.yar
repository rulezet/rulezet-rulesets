rule Win_Trojan_Stoned_56
{
strings:
	$a0 = { 0eea7c33ff8b1e13044b891e1304b90602d3e3891e727c8ec3c7064c00ca00891e4e00fcf3a4ea }


condition:
	$a0
}