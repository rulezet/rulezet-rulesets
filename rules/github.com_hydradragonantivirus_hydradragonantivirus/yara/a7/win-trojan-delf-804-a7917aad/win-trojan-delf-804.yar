rule Win_Trojan_Delf_804
{
strings:
	$a0 = { 8d55f4a1d0df4900e890d0ffff8d45ec50b928324900ba343249008b45f4e89ecfffff }


condition:
	$a0
}