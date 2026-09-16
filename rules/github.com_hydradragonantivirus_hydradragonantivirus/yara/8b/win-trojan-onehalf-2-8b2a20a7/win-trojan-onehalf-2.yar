rule Win_Trojan_OneHalf_2
{
strings:
	$a0 = { e74835f273337ae9a2978fb6aa51793c82f1062c6d1f2e1985f765a521750fd3835261c8c5508776cd796cd470d2e475 }


condition:
	$a0
}