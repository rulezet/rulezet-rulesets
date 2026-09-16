rule Win_Trojan_V_7
{
strings:
	$a0 = { ff80fcff740abaa70403d5b441cd21c3b4ffc3b80042 }


condition:
	$a0
}