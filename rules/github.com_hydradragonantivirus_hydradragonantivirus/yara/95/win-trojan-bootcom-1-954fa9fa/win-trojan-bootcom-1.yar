rule Win_Trojan_Bootcom_1
{
strings:
	$a0 = { 8cc8fa8ed0bc007cfb2e832e13????2ea1????b106d3e08ec0be007c33ff0e1fb90001f2a5b82b000650cb }


condition:
	$a0
}