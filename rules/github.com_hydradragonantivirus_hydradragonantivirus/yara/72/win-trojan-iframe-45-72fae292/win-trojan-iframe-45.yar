rule Win_Trojan_Iframe_45
{
strings:
	$a0 = { 3c696672616d6520207372633d226874 }

	$a1 = { 2f6e6f6f6e652e68746d6c }


condition:
	$a0 and $a1
}