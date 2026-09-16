rule Win_Trojan_Diamond_2
{
strings:
	$a0 = { 8ec28d77fdb90004f32ea41e8ed9be20 }


condition:
	$a0
}