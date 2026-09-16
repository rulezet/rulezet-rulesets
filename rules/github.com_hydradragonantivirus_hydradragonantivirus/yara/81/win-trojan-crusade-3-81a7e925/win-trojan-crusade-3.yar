rule Win_Trojan_Crusade_3
{
strings:
	$a0 = { bc007cfb8edba113042d0400a31304b106d3e0408ec006b80602b90c00ba8000cd13b82c0050 }


condition:
	$a0
}