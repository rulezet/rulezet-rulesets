rule Win_Trojan_Rukap_65
{
strings:
	$a0 = { bb6ffba1faa2c68a0b13dc0d4f3d8388773bf02e51405a5feba385520544d279fd3643651f3ccae5d806bfa408800e8a10119b452ecaa24fb5091ae4105e485ffd25edda26356dac }


condition:
	$a0
}