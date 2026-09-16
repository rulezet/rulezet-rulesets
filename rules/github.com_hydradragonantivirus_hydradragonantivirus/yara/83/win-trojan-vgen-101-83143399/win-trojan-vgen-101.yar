rule Win_Trojan_VGEN_101
{
strings:
	$a0 = { ca2e8916d602b430cd218b2e02008b1e2c008edaa3393b8c06373b891e333b892e533bc7063d3bffffe81301c43e31 }


condition:
	$a0
}