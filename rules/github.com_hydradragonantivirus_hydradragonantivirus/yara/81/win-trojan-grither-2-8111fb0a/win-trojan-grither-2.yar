rule Win_Trojan_Grither_2
{
strings:
	$a0 = { b430cd213c007503e9c50106b42f }


condition:
	$a0
}