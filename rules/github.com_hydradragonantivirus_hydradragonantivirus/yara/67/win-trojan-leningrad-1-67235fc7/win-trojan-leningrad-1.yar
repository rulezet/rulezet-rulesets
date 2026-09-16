rule Win_Trojan_Leningrad_1
{
strings:
	$a0 = { 8b36020181c61901b9bf05b0282e300446e2fa }


condition:
	$a0
}