rule Win_Trojan_Zamol_3
{
strings:
	$a0 = { 035856fa2e8c8c3109902e8c9c2f091e90b44990cd2190bbffff90b44890cd219081ebad00908cc190f913cb }


condition:
	$a0
}