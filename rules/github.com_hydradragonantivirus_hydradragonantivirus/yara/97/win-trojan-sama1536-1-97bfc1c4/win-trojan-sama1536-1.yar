rule Win_Trojan_SAMA1536_1
{
strings:
	$a0 = { d805ea744160be0500b91b00268a47052e88044643e2f52e880e0400060e072e8b2e03002e }


condition:
	$a0
}