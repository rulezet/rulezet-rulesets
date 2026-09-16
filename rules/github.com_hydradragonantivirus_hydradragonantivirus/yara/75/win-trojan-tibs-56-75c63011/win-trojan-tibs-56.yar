rule Win_Trojan_Tibs_56
{
strings:
	$a0 = { 89c189e58b6d1c83ed5f83ed644809ed75f8bf28acd10201c101f95189ceb90000000081c11ba52f0181e945a32f0141 }


condition:
	$a0
}