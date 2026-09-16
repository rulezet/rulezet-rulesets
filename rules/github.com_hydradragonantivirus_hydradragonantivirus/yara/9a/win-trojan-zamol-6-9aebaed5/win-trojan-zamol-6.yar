rule Win_Trojan_Zamol_6
{
strings:
	$a0 = { 5083ee035856fa2e8c8cf608902e8c9cf4081e90b44990cd2190bbffff90b44890cd219081eb9301908cc190f913 }


condition:
	$a0
}