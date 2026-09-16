rule Win_Trojan_Zamol_1
{
strings:
	$a0 = { 5083ee035856fa2e8c8c9207902e8c9c90071e90b44990cd2190bbffff90b44890cd219081eb8000908cc190f913cb }


condition:
	$a0
}