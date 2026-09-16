rule Win_Trojan_SillyC_243
{
strings:
	$a0 = { b44e33c95a81c2a300cd217228b8023dba9e00cd218bd8b43fb1055a5281c2b300cd21 }


condition:
	$a0
}