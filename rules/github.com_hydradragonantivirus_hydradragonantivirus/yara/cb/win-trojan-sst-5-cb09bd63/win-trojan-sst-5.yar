rule Win_Trojan_SST_5
{
strings:
	$a0 = { 03b93e02ba0001cd21be0e0203f58b0c80e1e080c1078b5402b80157cd218a261503cd21a1 }


condition:
	$a0
}