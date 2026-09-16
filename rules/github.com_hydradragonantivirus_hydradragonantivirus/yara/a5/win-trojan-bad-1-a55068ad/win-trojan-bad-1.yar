rule Win_Trojan_Bad_1
{
strings:
	$a0 = { 018b1fbe1f0103f3bf0001b90700f2a4e80300071fc3 }


condition:
	$a0
}