rule Win_Trojan_Renegade_4
{
strings:
	$a0 = { 2e8b16130483ea082e89161304b106d3e28ec233dbb80902b90900ba8000cd130668c602cb06 }


condition:
	$a0
}