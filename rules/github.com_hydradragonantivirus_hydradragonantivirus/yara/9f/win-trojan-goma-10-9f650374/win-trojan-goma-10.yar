rule Win_Trojan_Goma_10
{
strings:
	$a0 = { 89861607b440b910068d960501cd21b800429933c9cd21b440b91b00418d961207cd21e92cffcd }


condition:
	$a0
}