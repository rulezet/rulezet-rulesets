rule Win_Trojan_Label_3
{
strings:
	$a0 = { 35cd2126817f025a4b74722e8c86ff4a592e594a382f2fff33ed8eddc41dbf7402895dfc8c45feb4 }


condition:
	$a0
}