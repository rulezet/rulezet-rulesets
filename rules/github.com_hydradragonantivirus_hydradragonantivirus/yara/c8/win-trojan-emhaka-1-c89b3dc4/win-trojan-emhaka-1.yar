rule Win_Trojan_Emhaka_1
{
strings:
	$a0 = { 50535152b8ffffcd2109c074040ee89300fa2e8c94a1052e89a49f050e1789f481c43b00bb4d4731d2b9ab00 }


condition:
	$a0
}