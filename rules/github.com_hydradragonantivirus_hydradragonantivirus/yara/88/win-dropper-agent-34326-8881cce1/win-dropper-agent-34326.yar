rule Win_Dropper_Agent_34326
{
strings:
	$a0 = { 57ffd657ffd657ffd657ffd657ffd657ffd657ffd657ffd657ffd68b450c4875158d45fc5033c0505068c21f00105050ff1560400010 }


condition:
	$a0
}