rule Win_Adware_CloverPlus_2
{
strings:
	$a0 = { 636c6f7665725f75 }

	$a1 = { 687474703a2f2f636e742e636c6f766572706c75732e636f6d2f6c6f67 }


condition:
	$a0 and $a1
}