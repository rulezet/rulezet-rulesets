rule Win_Trojan_MRTI_1
{
strings:
	$a0 = { b90400bafb02e85200b43ee84d00b44fba5803b91000e84200e91bff0e1fa1f00240a3f0023d }


condition:
	$a0
}