rule Win_Trojan_FNS_1
{
strings:
	$a0 = { fd7797898653028d960501b90400b440cd218d960901b92701b440cd21b800429933c9cd218b }


condition:
	$a0
}