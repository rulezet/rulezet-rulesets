rule Win_Trojan_Timemark_1
{
strings:
	$a0 = { 4bcd217203eb6f9007068cc34b8edb8b1e030083eb }


condition:
	$a0
}