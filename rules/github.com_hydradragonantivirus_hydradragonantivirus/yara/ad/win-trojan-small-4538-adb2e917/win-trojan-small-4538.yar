rule Win_Trojan_Small_4538
{
strings:
	$a0 = { b8e6??400089c6ad83ec10ffd089c581c5 }


condition:
	$a0
}