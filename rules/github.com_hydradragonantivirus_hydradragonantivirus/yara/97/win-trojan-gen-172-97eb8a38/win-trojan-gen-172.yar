rule Win_Trojan_Gen_172
{
strings:
	$a0 = { 6c730e4f7574206f66204d656d6f7279215589e581ecae04bf00000e57b83f00508d7ed516579a }


condition:
	$a0
}