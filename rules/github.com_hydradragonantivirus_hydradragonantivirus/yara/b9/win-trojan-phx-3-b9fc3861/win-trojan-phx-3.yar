rule Win_Trojan_Phx_3
{
strings:
	$a0 = { 1aca80fc4b747d3d023d74433d74b9743680fc407405ea }


condition:
	$a0
}