rule Win_Trojan_Vgen_2
{
strings:
	$a0 = { e8b101e83101e85501ba6001e84201e84e00e89200e8b200e9e001e83801e8b201eb0c90e8c0013d02007503e9cc013d }


condition:
	$a0
}