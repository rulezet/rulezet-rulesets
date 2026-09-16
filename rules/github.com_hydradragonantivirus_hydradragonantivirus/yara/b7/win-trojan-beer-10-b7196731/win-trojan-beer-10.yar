rule Win_Trojan_Beer_10
{
strings:
	$a0 = { b95f0d2bcb2ea0de012e300743e2fa9d58595bc3e8e2ffb440b95f0dba03012bca8b1e780d }


condition:
	$a0
}