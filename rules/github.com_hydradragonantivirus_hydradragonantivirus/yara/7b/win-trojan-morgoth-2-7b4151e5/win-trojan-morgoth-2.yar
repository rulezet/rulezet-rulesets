rule Win_Trojan_Morgoth_2
{
strings:
	$a0 = { c437b9df008d960901cd21ebae33c09e9f86c40505 }


condition:
	$a0
}