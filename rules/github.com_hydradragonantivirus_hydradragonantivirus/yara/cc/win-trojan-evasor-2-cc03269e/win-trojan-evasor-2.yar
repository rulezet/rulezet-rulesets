rule Win_Trojan_Evasor_2
{
strings:
	$a0 = { 582d030195b9ffffeb0690b8004ccd21e2f68db633018bfeb9af00e80400eb1090 }


condition:
	$a0
}