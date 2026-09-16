rule Win_Trojan_Flow_6
{
strings:
	$a0 = { 40b926018d960301cd21b8004233c933d2cd21b440b903008d96c201cd21b43ecd21b44fcd21eb }


condition:
	$a0
}