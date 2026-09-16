rule Win_Trojan_Mandela_1
{
strings:
	$a0 = { 4d616e64656c61 }

	$a1 = { b982038db6????8bfeac2e32a6????aae2f7c3 }


condition:
	$a0 and $a1
}