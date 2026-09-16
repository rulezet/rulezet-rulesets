rule Win_Trojan_Trojan_264
{
strings:
	$a0 = { 1780fa007501c3cd2143e2f32ea1 }


condition:
	$a0
}