rule Win_Trojan_TB_2
{
strings:
	$a0 = { 351e2001cd35e8cd351e2801cd81e96200be5001cd96c7062e00014fcdc7c70660000100b88000 }


condition:
	$a0
}