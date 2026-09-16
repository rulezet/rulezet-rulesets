rule Win_Trojan_Packed_31
{
strings:
	$a0 = { 0fb7cf3e0facfd534a410fa4f7ed470facfd3b0fbdd50fc1c885c30fafef8d1d }


condition:
	$a0
}