rule Win_Trojan_Ply_4
{
strings:
	$a0 = { 08008cc890e9380d8ec090e968072be890e8340ee8c30ce9ca0503f590b99b01e90708240790e9710d569090e9ef04 }


condition:
	$a0
}