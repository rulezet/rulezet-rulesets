rule Win_Trojan_Hippie_1
{
strings:
	$a0 = { bc007c8ed3fb8edba113044848c1e00650538ec0b80302b9104fba0001cd13cb }


condition:
	$a0
}