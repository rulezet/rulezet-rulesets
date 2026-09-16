rule Win_Trojan_WarmBoot_1
{
strings:
	$a0 = { 58d18956d38a46ead4ea984fbaeb252dcdf80a5fd5e86bf518f224eefc84ffbcefbcf12d4c1383 }


condition:
	$a0
}