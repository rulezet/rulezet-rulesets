rule Win_Trojan_Taurus_1
{
strings:
	$a0 = { 017516be770203f38bf8a4a50e5033c033db33c933ff33f6cb538beb81fb0305730681c37702eb03bb0001b800 }


condition:
	$a0
}