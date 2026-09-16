rule Win_Trojan_Stinkfoot_4
{
strings:
	$a0 = { 59ba0400b435b024cd21061f890f89570261071fc31e }


condition:
	$a0
}