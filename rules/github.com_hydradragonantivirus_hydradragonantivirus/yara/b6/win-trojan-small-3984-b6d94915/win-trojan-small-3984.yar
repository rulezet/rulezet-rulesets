rule Win_Trojan_Small_3984
{
strings:
	$a0 = { e82d00000009c0742889c281c2fe??40008d8a7cf400ff8d890010ff005231c005ffdfadde2902c1020f8d520439 }


condition:
	$a0
}