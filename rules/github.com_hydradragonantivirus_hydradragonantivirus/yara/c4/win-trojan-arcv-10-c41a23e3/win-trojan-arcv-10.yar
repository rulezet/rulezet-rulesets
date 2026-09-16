rule Win_Trojan_Arcv_10
{
strings:
	$a0 = { be3301b9d4018034??46e2fac3 }


condition:
	$a0
}