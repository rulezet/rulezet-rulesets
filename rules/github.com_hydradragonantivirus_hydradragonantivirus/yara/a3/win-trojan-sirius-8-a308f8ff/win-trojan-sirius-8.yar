rule Win_Trojan_Sirius_8
{
strings:
	$a0 = { e800005d81ed08018db62601e80200eb108b961b02b9f5008bfeac32c2aae2fac3 }


condition:
	$a0
}