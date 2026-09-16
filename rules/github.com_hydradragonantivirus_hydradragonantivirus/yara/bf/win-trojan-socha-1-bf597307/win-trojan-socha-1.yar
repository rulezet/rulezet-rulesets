rule Win_Trojan_Socha_1
{
strings:
	$a0 = { c0bff5ff268b05474726330547472633 }


condition:
	$a0
}