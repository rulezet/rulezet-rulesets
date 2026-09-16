rule Win_Trojan_Taek_2
{
strings:
	$a0 = { 8cc133f32bd103d003d703c123f68bfa03fb23f933ff50402bf68bd2680800cb }


condition:
	$a0
}