rule Win_Trojan_PolyEngineSGen_10
{
strings:
	$a0 = { e8710033c0cd1680fc017503eb5e90ba4002e85f00b9320051b94a00be6802bf3108bd0001b8ff00e82a0486e0 }


condition:
	$a0
}