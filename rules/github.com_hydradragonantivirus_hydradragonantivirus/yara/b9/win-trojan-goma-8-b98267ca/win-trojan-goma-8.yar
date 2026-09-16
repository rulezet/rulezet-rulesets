rule Win_Trojan_Goma_8
{
strings:
	$a0 = { 96f8068986fa06b440b9f4058d960501cd21b800429933c9cd21b440b91b00418d96f606cd21e9 }


condition:
	$a0
}