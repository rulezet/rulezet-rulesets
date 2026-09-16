rule Win_Trojan_Pothia_1
{
strings:
	$a0 = { 25732063616e2774206265206f70656e65646e00 }


condition:
	$a0
}