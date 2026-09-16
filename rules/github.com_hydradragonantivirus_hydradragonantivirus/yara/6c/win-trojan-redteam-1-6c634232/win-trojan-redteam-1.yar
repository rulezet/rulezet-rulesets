rule Win_Trojan_RedTeam_1
{
strings:
	$a0 = { 75afc928db49b159eadc5c7734b9c6666e94381d74aebd872451 }


condition:
	$a0
}