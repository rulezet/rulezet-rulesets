rule Win_Trojan_Sistor_6
{
strings:
	$a0 = { e800005d81ed06008cc00510002e01869a00b430cd213c027703eb5a90b8534bcd2180fc497504eb4d90018cc0 }


condition:
	$a0
}