rule Win_Trojan_Tiny_60
{
strings:
	$a0 = { 0133ff8cda4a8eda8b571181ea8600fec6803d5a752f8edfc53684001e560e1fb954008ec18bf25756b178f3a65e }


condition:
	$a0
}