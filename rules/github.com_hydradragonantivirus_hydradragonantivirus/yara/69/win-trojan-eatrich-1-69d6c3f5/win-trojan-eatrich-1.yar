rule Win_Trojan_Eatrich_1
{
strings:
	$a0 = { 6202da287ef57ad0db6505d86279d8f5eadf9d39216f9b6269d86115d833c4db828163da8c33ccdb }


condition:
	$a0
}