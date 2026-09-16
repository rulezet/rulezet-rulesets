rule Win_Trojan_VGEN_98
{
strings:
	$a0 = { 061e0e8cc801063501ba3b0003c28bd8058b008edb8ec033f633ffb90800f3a54b484a79ee8ec38ed8be5200ad8be8 }


condition:
	$a0
}