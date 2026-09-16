rule Win_Trojan_Mybot_5917
{
strings:
	$a0 = { 1b8d975a75dc7b04a17d2d94e0336f513f6c73b033ef256f925a5d7afc3a225188420e0d08012dc4fd9108e21a7a6b26ffc6e40e8e0d69 }


condition:
	$a0
}