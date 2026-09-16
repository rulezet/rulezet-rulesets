rule Win_Trojan_Optimize_1
{
strings:
	$a0 = { 726520646561642e9a000052005589e5b800019a7c02520081ec0001bff8021e579ae5055200 }


condition:
	$a0
}