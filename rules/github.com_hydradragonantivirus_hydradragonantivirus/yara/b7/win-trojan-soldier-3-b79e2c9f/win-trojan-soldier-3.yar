rule Win_Trojan_Soldier_3
{
strings:
	$a0 = { 03b42ccd21f7d2f6c6087512f7d233da8bca80e2018af2b280b80605cd13b85aa5cd213da55a }


condition:
	$a0
}