rule Win_Trojan_Demonhyak_2
{
strings:
	$a0 = { 8916b801ba0001b440b91001cd21 }


condition:
	$a0
}