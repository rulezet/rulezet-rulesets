rule Win_Trojan_Anger_1
{
strings:
	$a0 = { e8fefeb80430cd2181fa0792742ab82135cd21891e2e018c063001b86d258bd3061fcd210e1fb82125ba0301cd6d }


condition:
	$a0
}