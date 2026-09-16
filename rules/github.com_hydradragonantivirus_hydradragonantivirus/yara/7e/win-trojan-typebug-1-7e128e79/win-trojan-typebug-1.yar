rule Win_Trojan_Typebug_1
{
strings:
	$a0 = { c7060a75f48be90000be1875b99f038034e346e2fa }


condition:
	$a0
}