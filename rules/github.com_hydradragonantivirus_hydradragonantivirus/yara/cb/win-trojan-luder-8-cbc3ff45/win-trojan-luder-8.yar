rule Win_Trojan_Luder_8
{
strings:
	$a0 = { 33c06a105950e2fd6a448bcc83ec108bd4[0-170]2e6578650000000000 }


condition:
	$a0
}