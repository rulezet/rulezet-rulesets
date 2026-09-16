rule Win_Trojan_Burglar_1
{
strings:
	$a0 = { c77003b90a00b87576902e31054790e2f958c390 }


condition:
	$a0
}