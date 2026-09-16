rule Win_Trojan_Proxy_72
{
strings:
	$a0 = { 006051508bc3b85ba79cd17900587b007e005903cb7400515781d7f0e47a670ffde6eb01ee5f0f57e0b902f0ca6059bf3fc0 }


condition:
	$a0
}