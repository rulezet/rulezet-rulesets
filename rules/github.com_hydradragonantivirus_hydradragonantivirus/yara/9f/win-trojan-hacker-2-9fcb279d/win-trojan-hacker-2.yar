rule Win_Trojan_Hacker_2
{
strings:
	$a0 = { d8b82135cd212e891e00022e8c060202b82125ba2601cd212eba0003cd27cd20c390909c3d004b2e74069d2eff }


condition:
	$a0
}