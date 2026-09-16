rule Win_Trojan_Terminator_7
{
strings:
	$a0 = { fbcf80fc4b740c80fc11740780fc4e7402eb2bfa50 }


condition:
	$a0
}