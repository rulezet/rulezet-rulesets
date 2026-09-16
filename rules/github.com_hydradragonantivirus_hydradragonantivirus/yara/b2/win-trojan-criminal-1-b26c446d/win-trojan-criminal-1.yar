rule Win_Trojan_Criminal_1
{
strings:
	$a0 = { eec604e9894401c74403ff20b442b0008b9e1f0bb90000 }


condition:
	$a0
}