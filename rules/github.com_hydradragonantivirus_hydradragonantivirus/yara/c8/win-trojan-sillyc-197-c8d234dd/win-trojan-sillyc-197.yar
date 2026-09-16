rule Win_Trojan_SillyC_197
{
strings:
	$a0 = { 63abf3108c2b35973529c68c6b9c2fa3e3abf725f8098f29352be39c7b913528f809de2c8167f809 }


condition:
	$a0
}