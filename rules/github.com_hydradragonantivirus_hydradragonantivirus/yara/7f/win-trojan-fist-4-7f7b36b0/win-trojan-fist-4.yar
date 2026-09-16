rule Win_Trojan_Fist_4
{
strings:
	$a0 = { 02b9f2fcccdc3e00fc7752e330c173dbfef31005381d85fd2d8863ab01d38f9f57038d3e488f26822ffe0381fda2 }


condition:
	$a0
}