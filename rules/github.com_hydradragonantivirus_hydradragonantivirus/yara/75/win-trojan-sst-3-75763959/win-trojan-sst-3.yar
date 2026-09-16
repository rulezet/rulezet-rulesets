rule Win_Trojan_SST_3
{
strings:
	$a0 = { 02b92102ba0001cd21bef20103f58b0c80e1e080c1078b5402b80157cd218a26f802cd21a1 }


condition:
	$a0
}