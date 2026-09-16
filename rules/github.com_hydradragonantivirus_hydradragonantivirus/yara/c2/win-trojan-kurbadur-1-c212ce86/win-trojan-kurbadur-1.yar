rule Win_Trojan_Kurbadur_1
{
strings:
	$a0 = { 7262616efd6e20434d4f5320752073696c69 }

	$a1 = { 8b45f4508b15ecb349008b12b9????49008b45fce864f5ffffe8????f6ffeb0b }


condition:
	$a0 and $a1
}