rule Win_Trojan_Pakes_921
{
strings:
	$a0 = { a73863442c7624521f0bff1febdc914d017e355e7e736d10d472e28b0031e8c48c6f60c44888303bf30c74d8dec51bf2 }


condition:
	$a0
}