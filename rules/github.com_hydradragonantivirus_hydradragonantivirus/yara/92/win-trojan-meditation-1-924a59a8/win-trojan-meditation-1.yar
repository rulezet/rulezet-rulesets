rule Win_Trojan_Meditation_1
{
strings:
	$a0 = { 83e90389cd2e898680048cc00510002e0186d000b021e8dd022e89be78042e89867a04b9ffffb800e0e8090081f996 }


condition:
	$a0
}