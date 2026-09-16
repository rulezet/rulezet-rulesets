rule Win_Trojan_Agent_36781
{
strings:
	$a0 = { 474d61496c2e634f4d }

	$a1 = { 677261627366616b75732e636f6d }


condition:
	$a0 and $a1
}