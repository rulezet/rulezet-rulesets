rule Win_Trojan_LordZer0_1
{
strings:
	$a0 = { 012ea3ba01b440b97201ba0001cd217212b8004233c933d2cd21b440b103bab901cd21b80057 }


condition:
	$a0
}