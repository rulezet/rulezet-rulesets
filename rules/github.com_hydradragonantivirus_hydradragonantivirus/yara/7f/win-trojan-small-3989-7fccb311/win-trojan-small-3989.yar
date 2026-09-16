rule Win_Trojan_Small_3989
{
strings:
	$a0 = { e82d00000009c0742889c281c2fe8140008d8a7cf400ff8d890010ff005231c005ffdfadde2902c1020f8d520439ca7e }


condition:
	$a0
}