rule Win_Trojan_DByte_1
{
strings:
	$a0 = { 33c0b805e0cd16b807e0cd1650558becc7460200f05d0733ffb8c800b9fffff3abb00150e670e47132c0e67158fec03c8075f033c033c9b002fa99cd26fb4183f90575f5c3 }


condition:
	$a0
}