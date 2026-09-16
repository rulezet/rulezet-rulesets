rule Win_Trojan_Tiny_22
{
strings:
	$a0 = { 01960e59f3a4ba4a01b44ecd217301cbb8023d99b29ecd2193b43fba50015459cd2105500050 }


condition:
	$a0
}