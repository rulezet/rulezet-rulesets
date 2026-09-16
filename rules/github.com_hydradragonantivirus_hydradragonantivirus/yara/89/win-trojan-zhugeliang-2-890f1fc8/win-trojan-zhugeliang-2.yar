rule Win_Trojan_Zhugeliang_2
{
strings:
	$a0 = { fbb80d6bbb120190e8480033ff268e452cb000b90080f2ae263a05e0f983c703061f0e07 }


condition:
	$a0
}