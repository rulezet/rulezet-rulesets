rule Win_Trojan_Milan_7
{
strings:
	$a0 = { 3d90cd219072bc908bd890b8005790cd219089160901 }


condition:
	$a0
}