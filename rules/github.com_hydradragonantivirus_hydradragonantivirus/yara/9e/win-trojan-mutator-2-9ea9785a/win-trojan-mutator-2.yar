rule Win_Trojan_Mutator_2
{
strings:
	$a0 = { ed0301e8ed0283161e00428ed242831e0b003bc086d8a90408b10cd3e0400b060e0023c27a4233c37b3e061fb23b }


condition:
	$a0
}