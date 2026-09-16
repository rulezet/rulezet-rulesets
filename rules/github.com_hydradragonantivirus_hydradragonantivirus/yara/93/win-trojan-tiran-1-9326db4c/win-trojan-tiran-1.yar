rule Win_Trojan_Tiran_1
{
strings:
	$a0 = { 090089869903b4408d960e01b95c05cd21b800422bc92bd2cd21b440b909008d969203cd21b801 }


condition:
	$a0
}