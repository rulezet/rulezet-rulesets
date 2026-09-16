rule Win_Trojan_Executioner_1
{
strings:
	$a0 = { 02eb02b000b4422bc92bd2cd21c3b440cd21c3b43fcd21c3b43ecd21c303002e003100310034 }


condition:
	$a0
}