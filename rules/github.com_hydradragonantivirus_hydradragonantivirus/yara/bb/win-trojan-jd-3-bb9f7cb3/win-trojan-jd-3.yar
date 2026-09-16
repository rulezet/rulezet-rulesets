rule Win_Trojan_JD_3
{
strings:
	$a0 = { 43008edb833d3d7408b425cd21b19e8ec30e1ff3a458 }


condition:
	$a0
}