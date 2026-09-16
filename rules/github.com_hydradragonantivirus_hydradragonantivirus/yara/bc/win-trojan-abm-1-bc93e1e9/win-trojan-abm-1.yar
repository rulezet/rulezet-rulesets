rule Win_Trojan_Abm_1
{
strings:
	$a0 = { 3a3b407a205b41424d20312e302064656d6f5d2062792044756b652f534d46 }


condition:
	$a0
}