rule Win_Trojan_Virut_390
{
strings:
	$a0 = { 33d2b204015424??e9??????00 }


condition:
	$a0
}