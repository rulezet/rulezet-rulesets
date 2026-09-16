rule Win_Trojan_Pentagon_1
{
strings:
	$a0 = { 723ccd0342fc8045fcfe000f586c43fc8242738045cafce2fb00 }


condition:
	$a0
}