rule Win_Trojan_Sanga_1
{
strings:
	$a0 = { 03fcf3a4071f582ea310002ec7060e00ac002eff1e0e002e8e061000b449cd212e8b1e12002e }


condition:
	$a0
}