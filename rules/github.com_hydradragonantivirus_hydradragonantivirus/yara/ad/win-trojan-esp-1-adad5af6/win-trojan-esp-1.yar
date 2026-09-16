rule Win_Trojan_ESP_1
{
strings:
	$a0 = { a3b205b90300bab105b440cd21b8024233d233c9cd21b4405a52b9fc202bca81c20001cd21 }


condition:
	$a0
}