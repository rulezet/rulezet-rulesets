rule Win_Trojan_SillyOC_38
{
strings:
	$a0 = { 5d81ed06018db68501be000157a5a48d968b01e85600b44e8d967f0133c9cd217247b8023d }


condition:
	$a0
}