rule Win_Trojan_Veronika_1
{
strings:
	$a0 = { e800005e06fa83ee0bb8bbfb16cd21fafc172e9c589e2ed194fc05565181c62f00b98b05e8ca05f9 }


condition:
	$a0
}