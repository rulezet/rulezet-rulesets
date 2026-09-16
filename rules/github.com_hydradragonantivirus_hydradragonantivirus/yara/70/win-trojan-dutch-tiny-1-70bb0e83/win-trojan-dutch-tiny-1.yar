rule Win_Trojan_Dutch_Tiny_1
{
strings:
	$a0 = { 5e81ee0c018bacc50581c50401e80300e9bd03505351568b9cc70581c6dc04b9e900d1e973 }


condition:
	$a0
}