rule Win_Trojan_Agent_34200
{
strings:
	$a0 = { 088b512c5268204b42006a006a006a006a00e8b912000083c41883f8017501cc }


condition:
	$a0
}