rule Win_Trojan_VGEN_161
{
strings:
	$a0 = { 290131d281c2770a8034418004c683eeff83c2ff7402ebf01901c1b37b0b7e7a65b53ed2ac0a461a637b7bd6fa660c }


condition:
	$a0
}