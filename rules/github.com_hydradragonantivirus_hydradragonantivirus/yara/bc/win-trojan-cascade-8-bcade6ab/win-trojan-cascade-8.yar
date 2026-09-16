rule Win_Trojan_Cascade_8
{
strings:
	$a0 = { 0f8dbcb601bc5a06313d3125474c75f8 }


condition:
	$a0
}