rule Win_Trojan_SillyC_84
{
strings:
	$a0 = { 12018bebbafaf7e894008db6ca01bf000157fca4a5b44e2bc98d96c401cd217302eb78a114f83d94007c103d35 }


condition:
	$a0
}