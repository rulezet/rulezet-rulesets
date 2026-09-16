rule Win_Trojan_Global_1
{
strings:
	$a0 = { 8916443ba001eb0e5fffeee963ff89ec5dc206000ba20e01050bf7b9ddde040bfed8b301a0f1 }


condition:
	$a0
}