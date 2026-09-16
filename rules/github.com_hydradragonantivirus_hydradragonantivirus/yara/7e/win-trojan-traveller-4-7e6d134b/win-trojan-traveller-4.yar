rule Win_Trojan_Traveller_4
{
strings:
	$a0 = { dbbb4000531ff647ff031f5b7503e836000af6750f83f901750a80fc05720af8eb22cd19ea }


condition:
	$a0
}