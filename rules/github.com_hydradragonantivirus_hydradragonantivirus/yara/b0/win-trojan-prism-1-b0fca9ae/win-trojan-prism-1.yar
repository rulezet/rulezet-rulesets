rule Win_Trojan_Prism_1
{
strings:
	$a0 = { 4e1fb262b90f9f81c11269eb02 }


condition:
	$a0
}