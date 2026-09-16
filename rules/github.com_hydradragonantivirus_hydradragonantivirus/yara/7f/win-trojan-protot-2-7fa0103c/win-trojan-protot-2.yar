rule Win_Trojan_ProtoT_2
{
strings:
	$a0 = { 56505351523d004b750d2e8c1e2c052e89162e05eb }


condition:
	$a0
}