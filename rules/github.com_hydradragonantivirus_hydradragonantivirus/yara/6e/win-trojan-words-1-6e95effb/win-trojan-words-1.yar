rule Win_Trojan_Words_1
{
strings:
	$a0 = { 0efe59588bc15e5d9dcf528bd6b4 }


condition:
	$a0
}