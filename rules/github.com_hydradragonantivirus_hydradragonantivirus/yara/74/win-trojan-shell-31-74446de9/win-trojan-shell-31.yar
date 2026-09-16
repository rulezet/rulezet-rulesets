rule Win_Trojan_Shell_31
{
strings:
	$a0 = { 3c3f2073797374656d28245f6765745b27636d64275d293b20646965202822 }


condition:
	$a0
}