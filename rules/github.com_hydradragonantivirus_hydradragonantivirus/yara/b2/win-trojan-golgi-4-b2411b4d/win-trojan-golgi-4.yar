rule Win_Trojan_Golgi_4
{
strings:
	$a0 = { 020200b440b9d101ba0001cc26c74515000026c745170000b440b90300bad102cc }


condition:
	$a0
}