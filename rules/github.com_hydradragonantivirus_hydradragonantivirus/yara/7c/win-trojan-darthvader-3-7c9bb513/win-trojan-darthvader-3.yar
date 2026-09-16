rule Win_Trojan_DarthVader_3
{
strings:
	$a0 = { 4075e381f9680172ddb82012cd2f26 }


condition:
	$a0
}