rule Win_Trojan_Made_2
{
strings:
	$a0 = { 0103de8b0733841b01890743b9490301f139cb7eee5bc3 }


condition:
	$a0
}