rule Win_Trojan_Small_155
{
strings:
	$a0 = { 015760fcbeff0003750166a533c98ec1bf0403b19badaf74174f4fabf3a48ed966a1840066a38803b82125ba3e03 }


condition:
	$a0
}