rule Win_Trojan_Agent_33641
{
strings:
	$a0 = { cf77afbaafc517fbddb297b5c7d3e9841a999af166bc4ab44a9dca4066199bb979b0c2baf57612ed29795f12a3fffabc8fe05ad2b36d9493d7c8ce552f4c1b29e81c25451be903f85e69b84c2095322b65e7 }


condition:
	$a0
}