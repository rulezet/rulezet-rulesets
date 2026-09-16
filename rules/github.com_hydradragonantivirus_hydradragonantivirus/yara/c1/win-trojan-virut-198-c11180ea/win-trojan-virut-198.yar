rule Win_Trojan_Virut_198
{
strings:
	$a0 = { e81a000000??8af2b9ea180000301002d640e2f9c30f31c383c8ffcd2eeb28558b6c2404816c2404????????e8e4ffffff8bc8e8ddffffff2bc13d0001000073510f00c167e3d1 }


condition:
	$a0
}