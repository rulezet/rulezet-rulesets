rule Win_Trojan_VGEN_505
{
strings:
	$a0 = { 55e800005d81ed0501e8e701e8ea03fcb80d90cd213dad0b7503e91d01b430cd213c037303e912 }


condition:
	$a0
}