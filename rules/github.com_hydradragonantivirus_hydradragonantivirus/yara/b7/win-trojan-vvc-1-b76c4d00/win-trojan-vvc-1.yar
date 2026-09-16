rule Win_Trojan_VVC_1
{
strings:
	$a0 = { 6f2030e448a20202a00300c43efa012688856f20bf38021e57b86f2031d252509a480d }


condition:
	$a0
}