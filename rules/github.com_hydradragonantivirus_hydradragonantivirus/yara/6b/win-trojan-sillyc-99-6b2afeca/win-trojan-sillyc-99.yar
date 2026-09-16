rule Win_Trojan_SillyC_99
{
strings:
	$a0 = { 023dcd21938bd581c2cb00b90400b43fcd213e8a86ce003c90751f8b4d168b5518b80157cd21b4 }


condition:
	$a0
}