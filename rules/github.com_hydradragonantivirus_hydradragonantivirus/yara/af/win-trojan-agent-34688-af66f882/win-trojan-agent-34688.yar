rule Win_Trojan_Agent_34688
{
strings:
	$a0 = { 558bec6aff68a0194000687852400064a100 }

	$a1 = { 70737267376a736162633763646430772e646c6c }


condition:
	$a0 and $a1
}