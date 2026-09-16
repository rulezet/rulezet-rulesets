rule Win_Trojan_Kuang_1
{
strings:
	$a0 = { abb84d00abb43cb92700ba8e02cd218bd8b440ba0000b9ce02cd21b80157b94150ba5448cd }


condition:
	$a0
}