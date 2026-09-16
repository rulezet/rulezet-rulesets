rule Win_Trojan_Drater_2
{
strings:
	$a0 = { 447261746572000000000000ffcc310012b5dab5bb0fa9c74892d7b024cb81dd6062a63ef1f6a2134cafc126e79a15606f3a4fad }


condition:
	$a0
}