rule Win_Trojan_Sahand_2
{
strings:
	$a0 = { 730bbb7373cd2180fc737403e96b080e581e5b2bc37518 }


condition:
	$a0
}