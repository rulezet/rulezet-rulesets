rule Win_Trojan_Mururoa_4
{
strings:
	$a0 = { 909090900001720b72188a050a167b1c1a1616d4d3d2edecefeee9e8ebeae5e4e7e6e1e0e3e2fdfcfffef9f8fb }


condition:
	$a0
}