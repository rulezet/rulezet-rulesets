rule Win_Trojan_VGEN_81
{
strings:
	$a0 = { 4b0e2bed178bf4e81100bdaffe8be6160bed74f681ed0c01eb0b905c448bfc4444574fffe7e8290c2b2bb81805bf4d }


condition:
	$a0
}