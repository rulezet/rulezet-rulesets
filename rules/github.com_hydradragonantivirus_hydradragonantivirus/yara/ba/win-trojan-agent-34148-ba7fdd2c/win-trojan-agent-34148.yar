rule Win_Trojan_Agent_34148
{
strings:
	$a0 = { e983010000e970010000706a5a6c4158 }


condition:
	$a0
}