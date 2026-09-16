rule Win_Trojan_SVC_12
{
strings:
	$a0 = { 84a60b2e8c84a80bc40620002e8984a20b2e8c84a40b }


condition:
	$a0
}