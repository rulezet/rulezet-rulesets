rule Win_Trojan_VGEN_186
{
strings:
	$a0 = { 1e068cc88ed88ec0be270003f58bfeb9ec0dfcad5058fa83ec0258fbf7d0fcabe2f0eb004184fefc0a46faff03 }


condition:
	$a0
}