rule Win_Trojan_Mybot_5920
{
strings:
	$a0 = { 64e9472af274091fbcdf62c8fa8dbbdd072a65ac2b24911d9dd4c0a3dfd18fbcb390f32fe5af925a6dfaccfa625188e2ae6da8d17da41d }


condition:
	$a0
}