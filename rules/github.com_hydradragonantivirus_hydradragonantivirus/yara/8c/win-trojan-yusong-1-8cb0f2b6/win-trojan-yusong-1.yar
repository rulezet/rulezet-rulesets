rule Win_Trojan_Yusong_1
{
strings:
	$a0 = { ba00012bcab4409cff1e0c01e872ffc38b1e1401b8 }


condition:
	$a0
}