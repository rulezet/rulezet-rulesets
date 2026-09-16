rule Win_Trojan_Sacrilege_1
{
strings:
	$a0 = { 0683c420b84a5fcd213bc37465061e5053515257568cc0488ec0268b1e030081ebfb06408ec0b44acd21b448bbfa }


condition:
	$a0
}