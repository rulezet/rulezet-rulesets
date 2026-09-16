rule Win_Trojan_OneHalf_4
{
strings:
	$a0 = { fc801f89de231a85ba719844646e5bdbe8982f294feedc8546b2026aa6f1ad43c85001fe6ac450bd815bd301df11a02a }


condition:
	$a0
}