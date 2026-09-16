rule Win_Trojan_Goma_9
{
strings:
	$a0 = { 89861507b440b90f068d960501cd21b800429933c9cd21b440b91b00418d961107cd21e92cffcd }


condition:
	$a0
}