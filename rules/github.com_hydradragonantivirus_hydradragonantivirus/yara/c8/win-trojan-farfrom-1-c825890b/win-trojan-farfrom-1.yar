rule Win_Trojan_FarFrom_1
{
strings:
	$a0 = { 3ea80400750757e8a1ff59eb428b36a6048bc60bc074318b048bd783c2283bc272095756e80dff }


condition:
	$a0
}