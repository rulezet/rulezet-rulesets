rule Win_Trojan_Bowl_5
{
strings:
	$a0 = { 81ed0601c686120101b800003d01007503e9ae02e89a02e880028bcb5f4c4dc0fb024ef24d4ce8e9c0db6049a5fb }


condition:
	$a0
}