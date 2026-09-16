rule Win_Trojan_Small_4464
{
strings:
	$a0 = { 60e8000000005b80fcc66629db53e9 }


condition:
	$a0
}