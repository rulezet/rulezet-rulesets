rule Win_Trojan_Chaploit_1
{
strings:
	$a0 = { 286d61696c2824636176792c[0-25]24796f75726d61 }

	$a1 = { 6b6f70656e28247365[0-28]2c20246f69322c203129 }


condition:
	$a0 and $a1
}