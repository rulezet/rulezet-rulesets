rule Win_Trojan_Tosha_1
{
strings:
	$a0 = { cd21b44fcd21e962ffb8024233c933d2cd213dc6fe73ce3d450176c950b4408bd5b9390190 }


condition:
	$a0
}