rule Win_Trojan_SillyRC_20
{
strings:
	$a0 = { 1992740d80fc4b7503e80800eaf840190086c4cf505351 }


condition:
	$a0
}