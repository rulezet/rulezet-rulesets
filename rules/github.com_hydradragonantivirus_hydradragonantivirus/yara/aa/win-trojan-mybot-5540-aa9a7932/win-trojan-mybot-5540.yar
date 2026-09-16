rule Win_Trojan_Mybot_5540
{
strings:
	$a0 = { bbd7cdf8c421dee87939dc39bbc32962c2b9c87c861bd971c86c93088b8c6ef7574edb5bb62cfff9a3fa941f7b42a5e90915abacaff3cdbf0c9f688a755248463b22f0e73bbb }


condition:
	$a0
}