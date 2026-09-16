rule Win_Trojan_Vik_2
{
strings:
	$a0 = { b8ddf0cd213c5174712bdb8b4f028edbc4064c00bf20032e89052e8c4502beb207ad8bd0ad3bd173068b143bd17207 }


condition:
	$a0
}