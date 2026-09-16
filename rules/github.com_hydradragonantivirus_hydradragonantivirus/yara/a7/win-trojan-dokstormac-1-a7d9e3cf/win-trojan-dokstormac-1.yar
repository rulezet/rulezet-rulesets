rule Win_Trojan_Dokstormac_1
{
strings:
	$a0 = { 7772557a32577a725935762f503345384c4f625757376e7248342f61 }


condition:
	$a0
}