rule Win_Trojan_Trojan_135
{
strings:
	$a0 = { 0350ff34e8900a83c4068bf8eb2c833e7a03007c1b7f08813e7803f82a7611b87c0350e8c9fe }


condition:
	$a0
}