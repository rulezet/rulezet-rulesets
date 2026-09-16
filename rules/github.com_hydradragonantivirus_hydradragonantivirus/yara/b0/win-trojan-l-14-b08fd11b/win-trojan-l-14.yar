rule Win_Trojan_L_14
{
strings:
	$a0 = { 5d81ed070188c988ed83fd0074080500000e07e8780519a8f0a391bc85b49fa3d091d0bb91bc9fd1f0b0f921f5 }


condition:
	$a0
}