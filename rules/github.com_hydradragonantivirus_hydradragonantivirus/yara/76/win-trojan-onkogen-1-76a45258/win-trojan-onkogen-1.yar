rule Win_Trojan_Onkogen_1
{
strings:
	$a0 = { 0e00720fbe2500bf8a06b90700f3a6f97401f8c3b43f9c2eff1e0e00c3b4409c2eff1e0e00 }


condition:
	$a0
}