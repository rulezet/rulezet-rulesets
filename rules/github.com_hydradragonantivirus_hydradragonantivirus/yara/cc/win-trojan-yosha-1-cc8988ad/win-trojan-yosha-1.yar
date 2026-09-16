rule Win_Trojan_Yosha_1
{
strings:
	$a0 = { 9952b601b9480151cd21b002e84800fec4a34602591f8bd7b440cd215a595840cd21b43ecd21 }


condition:
	$a0
}