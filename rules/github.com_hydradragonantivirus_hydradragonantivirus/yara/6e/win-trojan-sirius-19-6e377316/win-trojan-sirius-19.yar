rule Win_Trojan_Sirius_19
{
strings:
	$a0 = { 1700b2bfb6bd8d0ed80880b82e311781ea0e4883c302e2f44d9da32dc8646a9a783f6c9dcd2d0b71fb6665872e3587b533198fe157ca9a56da6453449b68d33d }


condition:
	$a0
}