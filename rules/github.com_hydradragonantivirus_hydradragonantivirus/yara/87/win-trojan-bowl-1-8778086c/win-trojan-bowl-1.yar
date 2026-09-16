rule Win_Trojan_Bowl_1
{
strings:
	$a0 = { 3e89868702b800429933c9cd21b90300b4408d968602cd21e86d00b99301b4408d960301cd21 }


condition:
	$a0
}