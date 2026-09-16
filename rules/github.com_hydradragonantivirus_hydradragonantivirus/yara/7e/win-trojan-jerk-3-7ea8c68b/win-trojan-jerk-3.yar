rule Win_Trojan_Jerk_3
{
strings:
	$a0 = { 03003e8986c201b440b925018d960301cd21b8004233c933d2cd21b440b903008d96c101cd21b4 }


condition:
	$a0
}