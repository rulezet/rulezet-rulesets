rule Win_Spyware_QQPass_41
{
strings:
	$a0 = { a1e8904000ba94634000e8c3d2ffff752c8d45f8baa8634000e888d0ffff8d4dfc33d28b45f8e843090000b9e8904000bac89040008d45fce8550c0000 }


condition:
	$a0
}