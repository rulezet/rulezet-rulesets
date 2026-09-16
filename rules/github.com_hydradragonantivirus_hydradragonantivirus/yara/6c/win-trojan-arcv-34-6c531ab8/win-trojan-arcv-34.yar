rule Win_Trojan_ARCV_34
{
strings:
	$a0 = { 87060400871e0600fa26a3550426891e5704fb1fc34576754c200058636f6e6e }


condition:
	$a0
}