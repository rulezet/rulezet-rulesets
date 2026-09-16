rule Win_Trojan_Shire_2
{
strings:
	$a0 = { ba98ffcd21b8e80450b44eba89012bc9cd21724ca0aeff40b44f241f74f0bab6ff }


condition:
	$a0
}