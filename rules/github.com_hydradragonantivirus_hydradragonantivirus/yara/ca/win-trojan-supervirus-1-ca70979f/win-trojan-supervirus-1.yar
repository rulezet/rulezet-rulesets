rule Win_Trojan_SuperVirus_1
{
strings:
	$a0 = { 03cd1373064f75f4f9eb18fec680fe0272eafec580fd1472e1b80f03b600b90100cd1307 }


condition:
	$a0
}