rule Win_Trojan_Xvxh_3
{
strings:
	$a0 = { b440cd21ccb9ffff2b4c09034c0781e9fe01c704e900894c018bd6b90300b440cd2133c933 }


condition:
	$a0
}