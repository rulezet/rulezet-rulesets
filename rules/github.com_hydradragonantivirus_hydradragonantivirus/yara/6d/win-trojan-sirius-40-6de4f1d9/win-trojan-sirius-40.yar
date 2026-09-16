rule Win_Trojan_Sirius_40
{
strings:
	$a0 = { 5369494343e302ebf5bb695334d28445694d6f9fd0b860eb6cad82afe99752b89d9fd15293e92c0aa445d16059ecfd4aa4 }


condition:
	$a0
}