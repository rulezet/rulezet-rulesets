rule Win_Trojan_Zhel_2
{
strings:
	$a0 = { 018aa42f0232c0e621e42102c430054702060401e621e2f132c0e621c3509cb0fee621b44f9d }


condition:
	$a0
}