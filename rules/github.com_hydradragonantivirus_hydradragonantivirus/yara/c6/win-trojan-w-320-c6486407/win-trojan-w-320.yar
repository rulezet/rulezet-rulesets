rule Win_Trojan_W_320
{
strings:
	$a0 = { 33c9b1b46033c0f3ae9cb44299ffd59d61750bf3a4894772b510b440ffd5b43e }


condition:
	$a0
}