rule Win_Trojan_Agent_34092
{
strings:
	$a0 = { c784240cfeffff42690700e9c0990200 }


condition:
	$a0
}