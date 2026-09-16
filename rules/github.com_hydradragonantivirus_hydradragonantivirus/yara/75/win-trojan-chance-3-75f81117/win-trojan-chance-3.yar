rule Win_Trojan_Chance_3
{
strings:
	$a0 = { f00326836f2302268b4723b106d3e050be007c8ec033ffb90001fcf3a5b86e0050cb2e8a2ef401 }


condition:
	$a0
}