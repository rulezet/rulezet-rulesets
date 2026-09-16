rule Win_Trojan_Baloo_4
{
strings:
	$a0 = { 3635045bc3b9ff01e8a8ff2efe063504e2f62efe0e3504c3b9ff01e895ff2efe0e3504e2f6c3 }


condition:
	$a0
}