rule Win_Trojan_Fraudload_5
{
strings:
	$a0 = { 6673643d223834313632376436363635376336 }

	$a1 = { 6673642e[0-10]32297b623d622b2225222b6673642e }


condition:
	$a0 and $a1
}