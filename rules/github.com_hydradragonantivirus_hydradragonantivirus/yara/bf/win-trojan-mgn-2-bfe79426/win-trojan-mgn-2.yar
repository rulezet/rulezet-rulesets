rule Win_Trojan_Mgn_2
{
strings:
	$a0 = { 851f003dff007414be430003f7b9bd09902e00042ef6 }


condition:
	$a0
}