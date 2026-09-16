rule Win_Trojan_Minzdrav_1
{
strings:
	$a0 = { 988b160101b440b9d001cd21728b39c875878b16010181c24301b440b90600cd21b43ecd21 }


condition:
	$a0
}