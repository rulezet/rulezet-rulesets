rule Win_Trojan_Subsys_11
{
strings:
	$a0 = { bdb76eedcba6f1ddd7e7fb493f7f740509c61ab04e7642128c31dd078179b1a1b3af2f2fad7dec8354248020e835e3df6879337c }


condition:
	$a0
}