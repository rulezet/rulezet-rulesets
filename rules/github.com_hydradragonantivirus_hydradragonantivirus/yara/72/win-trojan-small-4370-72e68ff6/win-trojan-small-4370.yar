rule Win_Trojan_Small_4370
{
strings:
	$a0 = { 91915850900f86010000009068f72641 }


condition:
	$a0
}