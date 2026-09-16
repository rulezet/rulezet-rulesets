rule Win_Trojan_SillyOC_11
{
strings:
	$a0 = { 21b8023dba9e01cd218bd8e83f00b440b98200ba0001cd21e83700e80f00b44febd5b409ba }


condition:
	$a0
}