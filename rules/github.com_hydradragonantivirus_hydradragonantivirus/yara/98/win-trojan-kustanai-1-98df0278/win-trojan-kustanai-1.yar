rule Win_Trojan_Kustanai_1
{
strings:
	$a0 = { 9dc2409440b8e8a7960a6b25ad3703c0c1d0186af6dd3c921097daa837aa7c6594c9dd9e21b0b5fb }


condition:
	$a0
}