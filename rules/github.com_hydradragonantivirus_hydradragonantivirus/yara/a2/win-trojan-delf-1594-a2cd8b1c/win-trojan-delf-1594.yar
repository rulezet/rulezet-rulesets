rule Win_Trojan_Delf_1594
{
strings:
	$a0 = { 68ccbe4b006a006a00e84cb0f4ff8bd8e875b1f4ff3db7000000740485db751053e8fcaff4ffe87b8af4ffe99d000000e815faffff84c07509e864f8ffff84c07450 }


condition:
	$a0
}