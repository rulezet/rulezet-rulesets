rule Win_Trojan_Akuku_2
{
strings:
	$a0 = { 40cd2172608bd683c214b440b90400cd21 }


condition:
	$a0
}