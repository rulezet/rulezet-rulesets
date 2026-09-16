rule Win_Trojan_Mstyle_4
{
strings:
	$a0 = { 0cec5ef690aa92dfa3d0cbba1336fdefe17fe35459b08f0c5fa9091ea007 }


condition:
	$a0
}