rule Win_Trojan_Paris_1
{
strings:
	$a0 = { 36b203cd218d3e0401aa3c087403eb }


condition:
	$a0
}