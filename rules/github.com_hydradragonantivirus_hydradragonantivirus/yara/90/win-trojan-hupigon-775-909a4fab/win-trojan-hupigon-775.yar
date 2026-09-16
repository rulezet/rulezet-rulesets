rule Win_Trojan_Hupigon_775
{
strings:
	$a0 = { 8b55f4b8a8bb4700e88295f8ff85c07fd38d4de8bab4bb47008b45f4e8c6cefdff8b55e88d45f4e8f78ff8ff837df4000f844f010000b201a150334100e82981f8ff }


condition:
	$a0
}