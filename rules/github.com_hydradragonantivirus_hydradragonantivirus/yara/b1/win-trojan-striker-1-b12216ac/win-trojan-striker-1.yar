rule Win_Trojan_Striker_1
{
strings:
	$a0 = { 5a8b460639c2740342ebe840894606a0 }


condition:
	$a0
}