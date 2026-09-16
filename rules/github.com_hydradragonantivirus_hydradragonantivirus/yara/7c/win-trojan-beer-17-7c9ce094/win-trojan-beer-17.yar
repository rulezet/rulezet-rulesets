rule Win_Trojan_Beer_17
{
strings:
	$a0 = { b9a50e2bcb2ea0de012e300743e2fa9d58595bc3e8e2ffb440b9a50eba03012bca8b1ebe0e }


condition:
	$a0
}