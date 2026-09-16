rule Win_Trojan_Agent_35459
{
strings:
	$a0 = { 3e0f2a042455575653e80d }

	$a1 = { 1b440d696789e7e1 }

	$a2 = { 5c0acebf4c7368d548 }


condition:
	$a0 and $a1 and $a2
}