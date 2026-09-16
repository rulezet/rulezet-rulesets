rule Win_Trojan_Hadi_1
{
strings:
	$a0 = { efbe1109cd2181f94148750881fa49447502eb77b448bb9f01cd217320b462cd218ec34b8edb8b }


condition:
	$a0
}