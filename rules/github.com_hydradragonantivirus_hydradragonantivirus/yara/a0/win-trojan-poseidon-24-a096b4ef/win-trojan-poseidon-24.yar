rule Win_Trojan_Poseidon_24
{
strings:
	$a0 = { 558bec81ecd40800008b450853568b35e81140005733ffc745f4d1000000897d }

	$a1 = { 8b6dfcffd55f5e5b8be55dc21000 }


condition:
	$a0 and $a1
}