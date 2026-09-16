rule Win_Trojan_SH_1
{
strings:
	$a0 = { 055052bacc03ec24017503f9eb0bbada03faeca80874fbfbf85a58c35052e8e0ff7266a0a70848a2a708a0a80848 }


condition:
	$a0
}