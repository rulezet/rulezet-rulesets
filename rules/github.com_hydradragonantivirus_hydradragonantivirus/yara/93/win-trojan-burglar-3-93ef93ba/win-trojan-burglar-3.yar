rule Win_Trojan_Burglar_3
{
strings:
	$a0 = { 0e1f33ffb93505fcf3a48ed9fa8c878400c787820058 }


condition:
	$a0
}