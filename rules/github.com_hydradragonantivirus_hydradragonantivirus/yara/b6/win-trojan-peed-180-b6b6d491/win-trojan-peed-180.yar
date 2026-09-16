rule Win_Trojan_Peed_180
{
strings:
	$a0 = { 558bec83ec2c535657 }

	$a1 = { c745ecb979379e }


condition:
	$a0 and $a1
}