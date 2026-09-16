rule Win_Trojan_Ascii_61_176_220_179_1
{
strings:
	$a0 = { 36312e3137362e3232302e313739 }


condition:
	$a0
}