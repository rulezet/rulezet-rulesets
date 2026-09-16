rule Win_Trojan_Hungarian_2
{
strings:
	$a0 = { 03f7ac0ac0740ad0e8b40eb307cd10ebf1b90100ba8000 }


condition:
	$a0
}