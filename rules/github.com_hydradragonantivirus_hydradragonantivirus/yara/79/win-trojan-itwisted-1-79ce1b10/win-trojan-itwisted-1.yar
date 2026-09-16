rule Win_Trojan_Itwisted_1
{
strings:
	$a0 = { 22018d960001cd21b8002ccd218aca8ac1b8002ccd218aca02c8d0c932ed33d2b440cd21 }


condition:
	$a0
}