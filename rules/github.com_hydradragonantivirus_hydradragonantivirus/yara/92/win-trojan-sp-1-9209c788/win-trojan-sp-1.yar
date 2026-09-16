rule Win_Trojan_SP_1
{
strings:
	$a0 = { 130490a11304b106d3e08ec0be007c33ffb90002f3a406b8610050cbb88d0087064c0026a315 }


condition:
	$a0
}