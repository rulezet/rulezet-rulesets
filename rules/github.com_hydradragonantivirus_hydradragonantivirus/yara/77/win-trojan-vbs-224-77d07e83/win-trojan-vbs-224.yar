rule Win_Trojan_VBS_224
{
strings:
	$a0 = { 65786563757465206e756d327374722868717773747229 }


condition:
	$a0
}