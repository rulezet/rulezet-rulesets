rule Win_Trojan_WMA_1
{
strings:
	$a0 = { 02b90100ba8000cd13721a26803fe87414b8010341cd138bfbb9d4002ef3a5b8010341cd13b8 }


condition:
	$a0
}