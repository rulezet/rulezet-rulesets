rule Win_Trojan_N_53
{
strings:
	$a0 = { b901008bd1bbd80dac0e1fe82e06cd25732380fc02f9751d58e83406891ec40dbbbe0d8917 }


condition:
	$a0
}