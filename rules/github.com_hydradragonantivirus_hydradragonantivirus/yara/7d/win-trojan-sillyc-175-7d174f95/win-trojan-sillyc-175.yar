rule Win_Trojan_SillyC_175
{
strings:
	$a0 = { cd21b8004fcd217205e80a0075f0ba8000b41acd21c3b8003d8d969e00cd218bd88b8e9a0081f9 }


condition:
	$a0
}