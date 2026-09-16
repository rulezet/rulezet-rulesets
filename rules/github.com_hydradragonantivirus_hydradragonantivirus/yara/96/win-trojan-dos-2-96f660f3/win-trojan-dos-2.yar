rule Win_Trojan_DoS_2
{
strings:
	$a0 = { 356d740f01d3f2b8f9a4e4ce38db52ce5bda00c9ffbbf49221014faad05d32ea5ce46bf597767f81ac61ce60b743011da5347703e963641fd6f9886622e66348 }


condition:
	$a0
}