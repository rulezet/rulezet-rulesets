rule Win_Trojan_Pinquin_1
{
strings:
	$a0 = { 7c33c0fa8ed08be6fb8ed8832e130402cd12b106d3e08ec032f680fa80740033dbb80202b903 }


condition:
	$a0
}