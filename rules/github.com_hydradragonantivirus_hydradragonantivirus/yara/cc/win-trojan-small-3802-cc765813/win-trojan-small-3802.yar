rule Win_Trojan_Small_3802
{
strings:
	$a0 = { b64238fd58176cbce702b2e8585d66f66ec16efa2c7e1ca122fd4c8e2c761cbd2c04b3e19ffebd64d3170365d01369fa4f0d38ada7813e55fe5bb5eaa3e93a9e675d666e2c461ca5f1894c89af55 }


condition:
	$a0
}