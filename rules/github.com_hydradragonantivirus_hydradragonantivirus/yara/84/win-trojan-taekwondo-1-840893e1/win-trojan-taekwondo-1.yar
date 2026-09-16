rule Win_Trojan_Taekwondo_1
{
strings:
	$a0 = { bc007ca1130448a31304b106d3e08ec006fcbe007cbf0000b90002f3a4bb460053cba14c00a31401 }


condition:
	$a0
}