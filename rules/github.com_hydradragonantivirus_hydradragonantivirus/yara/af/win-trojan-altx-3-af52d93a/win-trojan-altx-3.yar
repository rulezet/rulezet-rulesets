rule Win_Trojan_Altx_3
{
strings:
	$a0 = { 0eb80014b104d3e88ccb83c31003d853b8040050cb }


condition:
	$a0
}