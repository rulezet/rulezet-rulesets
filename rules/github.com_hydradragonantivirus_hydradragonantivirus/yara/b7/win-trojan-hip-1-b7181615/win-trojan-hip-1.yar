rule Win_Trojan_Hip_1
{
strings:
	$a0 = { febedf0089f788c4ac32c4aae2fab8004299cd21b4405a5981c1c800cd21b43ecd21b44feb8f }


condition:
	$a0
}