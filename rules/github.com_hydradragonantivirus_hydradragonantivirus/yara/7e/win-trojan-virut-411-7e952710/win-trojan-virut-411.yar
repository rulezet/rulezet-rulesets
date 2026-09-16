rule Win_Trojan_Virut_411
{
strings:
	$a0 = { 89db8d1283ec2ce85f020000016c242020e5035c24fc2adb09c6b50e81eb800000000fb78b }


condition:
	$a0
}