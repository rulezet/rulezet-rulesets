rule Win_Trojan_Neuroquila_9
{
strings:
	$a0 = { 8ed0bc007cfb8ec40668160293b80902b90800ba8000cd1372fecb }


condition:
	$a0
}