rule Win_Trojan_I13_19
{
strings:
	$a0 = { 1304b106d3e08ec0be007c33ffb90001f3a506bb660053cb46a14c0026a3f700c7064c00 }


condition:
	$a0
}