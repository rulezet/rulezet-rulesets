rule Win_Trojan_Bancos_1743
{
strings:
	$a0 = { 069ee10622dc1a913f307acc9ec94a0ff077d71c9e32ab075149689b7ce0f6c4a12a14feed7586d8a517e669555a6fdf81bbc7d8ff86ba31f5b283daea81f4a97f3a2578842c }


condition:
	$a0
}