rule Win_Trojan_Nomad_4
{
strings:
	$a0 = { 03b800429933c9cd21b440b91c008d96e903cd21b801578b8ed4038b96d60380e1e080c910cd21b4 }


condition:
	$a0
}