rule Win_Trojan_KO_2
{
strings:
	$a0 = { 53b8024233c9baffffcd218bd033c9b80042cd210e1fb4 }


condition:
	$a0
}