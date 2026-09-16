rule Win_Trojan_Chapa_2
{
strings:
	$a0 = { c6061f0200b440b9c0010e1fba00020ee84cffe86effb440b9c001ba00bf8eda33d20ee839ff }


condition:
	$a0
}