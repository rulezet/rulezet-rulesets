rule Win_Trojan_DarkRevenge_1
{
strings:
	$a0 = { a12901250f002bd033c98b1e2b01b80242cd21ba0001b90004908b1e2b01b440cd215a59 }


condition:
	$a0
}