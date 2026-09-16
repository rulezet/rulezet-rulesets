rule Win_Trojan_Hanko_1
{
strings:
	$a0 = { b9db07bdf8038dbe1d012e310547472ec6861a01e9e2f3e98400 }


condition:
	$a0
}