rule Win_Trojan_Demented_1
{
strings:
	$a0 = { 408d96c702b90500cd21b002e82600b440b958018d960501cd21b801578b8eb3028b96b502cd21 }


condition:
	$a0
}