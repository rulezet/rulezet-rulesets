rule Win_Trojan_Minimal_10
{
strings:
	$a0 = { 010100550000000000ffff3203000065000000050000003203 }


condition:
	$a0
}