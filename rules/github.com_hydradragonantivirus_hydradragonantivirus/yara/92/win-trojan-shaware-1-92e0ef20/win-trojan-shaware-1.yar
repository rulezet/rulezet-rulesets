rule Win_Trojan_Shaware_1
{
strings:
	$a0 = { 4b740b3d003d74069d2eff2ec2029d2e8c1ec8020e1f }


condition:
	$a0
}