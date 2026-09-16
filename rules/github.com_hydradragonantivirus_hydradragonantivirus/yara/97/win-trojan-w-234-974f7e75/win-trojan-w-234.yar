rule Win_Trojan_W_234
{
strings:
	$a0 = { 14124100e89623ffffa16036410050b928124100ba3c1241008bc3e85bf6ffff6a01b94c124100ba3c1241 }


condition:
	$a0
}