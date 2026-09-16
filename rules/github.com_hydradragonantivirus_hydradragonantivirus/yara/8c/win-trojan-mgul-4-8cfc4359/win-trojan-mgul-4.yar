rule Win_Trojan_MGUL_4
{
strings:
	$a0 = { 83ee03fc5053b8bbaacd213d3df5743d561e068cc0488ec0bb030026832f504b8b072d500089078ec00e1f33ffb9b6 }


condition:
	$a0
}