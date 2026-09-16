rule Win_Trojan_CrazyFrog_1
{
strings:
	$a0 = { 052e8b8670052e31142e31440283c604e2f4c3e440 }


condition:
	$a0
}