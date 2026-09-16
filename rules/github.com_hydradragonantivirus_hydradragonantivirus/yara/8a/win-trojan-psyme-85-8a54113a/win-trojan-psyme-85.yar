rule Win_Trojan_Psyme_85
{
strings:
	$a0 = { 2e6f70656e2022676574 }

	$a1 = { 736765742e73617665746f66696c6520222e5c782e69636f222c32 }


condition:
	$a0 and $a1
}