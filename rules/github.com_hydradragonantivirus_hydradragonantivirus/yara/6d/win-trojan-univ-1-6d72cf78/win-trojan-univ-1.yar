rule Win_Trojan_Univ_1
{
strings:
	$a0 = { 4233c999cd21b4408d96f301b90500cd21b8024233c999cd21b440b932038d960501cd21b801 }


condition:
	$a0
}