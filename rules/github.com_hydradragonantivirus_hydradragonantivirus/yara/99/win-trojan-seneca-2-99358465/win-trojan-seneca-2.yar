rule Win_Trojan_Seneca_2
{
strings:
	$a0 = { 01b9b6018a2780f4ff882743e2f6c38b1ee30253e8e7ff5bb9e301ba0001b440cd21e8d9ffc3 }


condition:
	$a0
}