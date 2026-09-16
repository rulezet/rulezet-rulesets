rule Win_Trojan_Virut_388
{
strings:
	$a0 = { 33c0b004014424??e9??????00 }


condition:
	$a0
}