rule Win_Trojan_SST_6
{
strings:
	$a0 = { 03b94e02ba0001cd21be1e0203f58b0c80e1e080c1078b5402a12803cd218a262503cd21a1 }


condition:
	$a0
}