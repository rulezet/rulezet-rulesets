rule Win_Trojan_Suicidal_3
{
strings:
	$a0 = { 5d81ed06018db6ec03bf000157a5a4ba4559b801facd16b41a8d960e04cd21b44732d28db67e04cd212ec6063e0400 }


condition:
	$a0
}