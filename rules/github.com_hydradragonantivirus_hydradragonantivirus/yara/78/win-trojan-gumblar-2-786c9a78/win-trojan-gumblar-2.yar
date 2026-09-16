rule Win_Trojan_Gumblar_2
{
strings:
	$a0 = { 6426326626326667756d626c61722632652636336e }

	$a1 = { 756e657363617065286465657a29297d }


condition:
	$a0 and $a1
}