rule Win_Trojan_Hezhi_1
{
strings:
	$a0 = { 81c62405457981ee2405457960f59090f59c57 }

	$a1 = { 494b65726e656c2e65785f }

	$a2 = { 257373657475702e626d70 }


condition:
	$a0 and $a1 and $a2
}