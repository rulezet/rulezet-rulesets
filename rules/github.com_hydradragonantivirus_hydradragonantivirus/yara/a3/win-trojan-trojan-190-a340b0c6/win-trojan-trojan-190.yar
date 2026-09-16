rule Win_Trojan_Trojan_190
{
strings:
	$a0 = { 575153508b5e028a07750e93bfe700b92100f2afff45bc8ac598400146 }


condition:
	$a0
}