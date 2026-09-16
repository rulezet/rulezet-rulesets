rule Win_Trojan_VCL_3
{
strings:
	$a0 = { 89960003b8024233c999cd21e4403e88863e01b4408d960301b93c00cd218dbe4503578db63f01 }


condition:
	$a0
}