rule Win_Trojan_Barjam_1
{
strings:
	$a0 = { 80ff9a15001402e878ffb808009952500eb8dd20509a2f001402e865ffb85600509ae9171402 }


condition:
	$a0
}