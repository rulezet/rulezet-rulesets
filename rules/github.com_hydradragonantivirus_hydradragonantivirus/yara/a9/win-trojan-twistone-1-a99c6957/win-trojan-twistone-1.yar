rule Win_Trojan_Twistone_1
{
strings:
	$a0 = { b926018d960001cd21b8002ccd218aca8ac1b8002ccd218aca02c8d0c932ed33d2b440cd21 }


condition:
	$a0
}