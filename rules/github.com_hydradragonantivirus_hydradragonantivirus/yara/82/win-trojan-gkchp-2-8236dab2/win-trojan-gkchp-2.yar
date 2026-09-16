rule Win_Trojan_Gkchp_2
{
strings:
	$a0 = { 8cd80518018ed8bb2801b9840190a1140131074343e2fa }


condition:
	$a0
}