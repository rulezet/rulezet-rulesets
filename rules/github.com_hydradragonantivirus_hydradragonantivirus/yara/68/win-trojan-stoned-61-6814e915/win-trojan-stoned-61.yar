rule Win_Trojan_Stoned_61
{
strings:
	$a0 = { 0433ff33f648b106a31304d3e08ec087064e00a3437db8d90087064c00a3417d0e1fb90002f3 }


condition:
	$a0
}