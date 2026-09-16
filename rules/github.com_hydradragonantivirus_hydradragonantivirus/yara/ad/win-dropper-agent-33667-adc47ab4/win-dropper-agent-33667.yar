rule Win_Dropper_Agent_33667
{
strings:
	$a0 = { ffffff32c0f2ae8d47ff89d7c390568bf092e83390ffff8bc65ec38d4000575689c689d7b9ffffffff32c0f2aef7d189f789d689ca89f8c1e902f3a589d183e103f3a45e5fc357565389c689d789cb32 }


condition:
	$a0
}