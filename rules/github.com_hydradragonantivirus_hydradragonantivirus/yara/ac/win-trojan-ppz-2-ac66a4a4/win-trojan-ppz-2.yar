rule Win_Trojan_PPZ_2
{
strings:
	$a0 = { 75636b696e672062792050505a5589e581ec0e018d7efa16578d7ef816578d7ef616578d7ef416 }


condition:
	$a0
}