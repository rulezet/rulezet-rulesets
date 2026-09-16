rule Win_Trojan_RSCdoor_6
{
strings:
	$a0 = { 341804e801b3226530f9ff0fd238673a8faa5baa57438eabbcc06fe013f27ff2273901536572766572ffcc310002ffff }


condition:
	$a0
}