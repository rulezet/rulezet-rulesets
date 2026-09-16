rule Win_Trojan_SillyC_236
{
strings:
	$a0 = { 8b84cd00a300018a84cf00a20201b41a8d94dc00cd21b44eb937008d94d300cd217303e99a00b800438d94fa00cd21 }


condition:
	$a0
}