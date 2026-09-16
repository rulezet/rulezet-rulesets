rule Win_Trojan_Ass_1
{
strings:
	$a0 = { 8b8bf28b0432c43c17740bb80057cd8b83f11ff6c1 }


condition:
	$a0
}