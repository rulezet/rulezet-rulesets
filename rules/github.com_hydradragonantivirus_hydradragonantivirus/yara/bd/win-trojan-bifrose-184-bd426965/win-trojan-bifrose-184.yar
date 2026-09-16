rule Win_Trojan_Bifrose_184
{
strings:
	$a0 = { db00153c13fcf7aea69b0ff4aad18e25738cc0f0e60bbab8b30e9c2fed930b5200895756e9220049410d08eece5c040980e6c5c180c86a0331fa00297de058eab5709c00 }


condition:
	$a0
}