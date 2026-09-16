rule Win_Trojan_ATRAPS_1
{
strings:
	$a0 = { 5031001083c9ff33c0be50310010f2aef7d1498dbc24b80200008bd150c1e902f3a58b }


condition:
	$a0
}