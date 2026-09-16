rule Win_Trojan_FidoSpy_1
{
strings:
	$a0 = { 4c8f338fa30425acd604f0056e200946887af9087047c490befcbefa641ce5485fcf0128dae2ad }


condition:
	$a0
}