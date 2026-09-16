rule Win_Trojan_Banload_2082
{
strings:
	$a0 = { 558becb8f088ebc9bb8cfc1efe50e800000000582da81a0000b96d }


condition:
	$a0
}