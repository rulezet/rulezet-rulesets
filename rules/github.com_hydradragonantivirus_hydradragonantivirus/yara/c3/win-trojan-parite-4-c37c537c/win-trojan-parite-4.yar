rule Win_Trojan_Parite_4
{
strings:
	$a0 = { 021cbd2c9a60ffeb168b56bbe9d2c8bde91ac2129b605004cd9e00ecef47843711b8576121575061f15dfe139bcde826659f0068a4eb12ba33124d243512852e }


condition:
	$a0
}