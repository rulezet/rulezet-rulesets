rule Win_Trojan_MGUL_3
{
strings:
	$a0 = { e800005e83ee03fc5053b8bbaacd213d34fd7465561e068cc0488ec0bb030026812f80004b8b072d800089078ec00e1f }


condition:
	$a0
}