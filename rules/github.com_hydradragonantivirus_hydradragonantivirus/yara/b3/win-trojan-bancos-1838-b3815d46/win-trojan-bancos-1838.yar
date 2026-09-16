rule Win_Trojan_Bancos_1838
{
strings:
	$a0 = { 3d101651b30b1d292b41d09d0547edfd4c05ba5edcdd87a3ead80bc96f0afdce077e6e3993762e029c44964e264af90c79525ead6e1669c39f62b9af76dee69dc8ab7cbfb3ea }


condition:
	$a0
}