rule Win_Trojan_Bowl_2
{
strings:
	$a0 = { 89868802b800429933c9cd21b90300b4408d968702cd21e86d00b99401b4408d960301cd21 }


condition:
	$a0
}