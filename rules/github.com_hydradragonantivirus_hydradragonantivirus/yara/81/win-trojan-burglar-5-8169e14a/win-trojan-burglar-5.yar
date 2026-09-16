rule Win_Trojan_Burglar_5
{
strings:
	$a0 = { d088441233d2b90903b440cd21b000e80d00ba0903b91800b440cd21e90eff33c933d2b442cd21 }


condition:
	$a0
}