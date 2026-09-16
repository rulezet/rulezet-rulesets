rule Win_Trojan_Moonlite_2
{
strings:
	$a0 = { eb2b90e811008d960301b9a101b440cd21e80300c3 }


condition:
	$a0
}