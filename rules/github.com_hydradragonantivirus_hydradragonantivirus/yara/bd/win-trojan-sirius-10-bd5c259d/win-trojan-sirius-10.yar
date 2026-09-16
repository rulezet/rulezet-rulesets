rule Win_Trojan_Sirius_10
{
strings:
	$a0 = { 81ed09018db68701bf0001fca4a4a4a4b44e33c98d968b01cd217303eb5690b8023dba9e00cd218bd8b43fb904008d }


condition:
	$a0
}