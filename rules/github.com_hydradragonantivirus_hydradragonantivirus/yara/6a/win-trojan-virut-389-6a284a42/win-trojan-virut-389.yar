rule Win_Trojan_Virut_389
{
strings:
	$a0 = { 33dbb304015c24??e9??????00 }


condition:
	$a0
}