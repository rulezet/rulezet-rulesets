rule Win_Trojan_Childsplay_2
{
strings:
	$a0 = { 32c0e84300b440b903008d96b002cd21b002e8330053e817005bb4408d960301b9ae01cd }


condition:
	$a0
}