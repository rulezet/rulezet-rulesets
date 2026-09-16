rule Win_Trojan_Birgit_21
{
strings:
	$a0 = { e2fdba0d02ffd2c353baf501ffd25bb440b90d01ba0001cd2153baf501ffd25bc3 }


condition:
	$a0
}