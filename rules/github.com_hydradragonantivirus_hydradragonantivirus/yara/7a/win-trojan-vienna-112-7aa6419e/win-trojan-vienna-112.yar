rule Win_Trojan_Vienna_112
{
strings:
	$a0 = { 80f2aeb90400acae75e3e2fa83ff05740726807dfa }


condition:
	$a0
}