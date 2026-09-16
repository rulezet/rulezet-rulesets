rule Win_Trojan_FakeVirX_2
{
strings:
	$a0 = { aa58050001abb8ffe7ab8bfeb800 }


condition:
	$a0
}