rule Win_Trojan_Havex_1
{
strings:
	$a0 = { 8bff558bec837d0c017505e8(7f|8f)830000ff75088b4d108b550ce8ecfeffff595dc20c00ff35a4da0410 }


condition:
	$a0
}