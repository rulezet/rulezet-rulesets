rule Win_Trojan_IRCBot_255
{
strings:
	$a0 = { 688880400052ffd3578d4604686c80400050ffd383c43c }


condition:
	$a0
}