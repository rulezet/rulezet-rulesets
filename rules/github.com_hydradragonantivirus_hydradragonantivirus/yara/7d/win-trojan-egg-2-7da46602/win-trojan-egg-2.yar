rule Win_Trojan_Egg_2
{
strings:
	$a0 = { baad01e82401c6067b01f9e82e01b440b90300bae504e81101e81501b9e803b440ba0001 }


condition:
	$a0
}