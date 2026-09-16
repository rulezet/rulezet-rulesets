rule Win_Trojan_Russel_3
{
strings:
	$a0 = { 1b1428bc6f4eefdf3485291b6f48b0a1605f85dc735f75e0735f7de2734c702b3485faf177e01bd2 }


condition:
	$a0
}