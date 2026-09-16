rule Win_Trojan_Gift_2
{
strings:
	$a0 = { 500090f3a407b8004233d233c9cd218bcfba00012bcab440cd21b80157268b4e16268b5618cd21 }


condition:
	$a0
}