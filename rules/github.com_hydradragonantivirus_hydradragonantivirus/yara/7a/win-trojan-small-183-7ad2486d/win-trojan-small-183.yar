rule Win_Trojan_Small_183
{
strings:
	$a0 = { a4ebda608bf2ac3de940750a1e0e1f99b93b00cd211f }


condition:
	$a0
}