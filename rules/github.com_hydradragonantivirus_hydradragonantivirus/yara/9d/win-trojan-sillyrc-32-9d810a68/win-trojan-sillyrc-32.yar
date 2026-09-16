rule Win_Trojan_SillyRC_32
{
strings:
	$a0 = { 35cd211e075d81ed03013dff257535061f8d9e5b0233c033c90b070a6f02bb01018367ff00806701008947ff886f }


condition:
	$a0
}