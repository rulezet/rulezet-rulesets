rule Win_Trojan_Mururoa_8
{
strings:
	$a0 = { 50b44abb8b0dcd217308b409ba309bcd21c3eb01cf31c08ec026c7068c001a01268c0e8e008cc88ec0bf1cb9 }


condition:
	$a0
}