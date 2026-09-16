rule Win_Trojan_ScreenAllive_1
{
strings:
	$a0 = { 579a400a4101741bbfa60a0e57e894f508c0740fbfcc021e57bfa60a0e576a00e8e4f6c9 }


condition:
	$a0
}