rule Win_Trojan_SillyC_44
{
strings:
	$a0 = { 40b98f008d960401cd21b8004233c999cd21b440b90400 }


condition:
	$a0
}