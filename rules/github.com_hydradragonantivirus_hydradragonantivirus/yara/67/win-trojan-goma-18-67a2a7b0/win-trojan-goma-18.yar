rule Win_Trojan_Goma_18
{
strings:
	$a0 = { 5c03b440b956028d960501cd21b800429933c9cd21b440b91b00418d965803cd21e93cffcd21 }


condition:
	$a0
}