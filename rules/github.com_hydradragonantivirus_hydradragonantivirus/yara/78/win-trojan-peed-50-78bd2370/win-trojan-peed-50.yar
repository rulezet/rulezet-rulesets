rule Win_Trojan_Peed_50
{
strings:
	$a0 = { 8b6c241c83ed2d83ed3283ed504883ed }


condition:
	$a0
}