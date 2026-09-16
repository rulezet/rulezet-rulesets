rule Win_Trojan_VCode_1
{
strings:
	$a0 = { 01018b3581c60301b8effecd2180fc19753981c69500bf000157b90300f3a4c3fc33f6b8effecd2180fc19751e8c }


condition:
	$a0
}