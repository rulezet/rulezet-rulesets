rule Win_Trojan_Problem_1
{
strings:
	$a0 = { cf9c2e803e12030074029dcf552e892eea0233ed80fc }


condition:
	$a0
}