rule Win_Trojan_G_14
{
strings:
	$a0 = { 6efa81ed1300061eb84144cd213d535074508cd8488ed8832e030045832e1200 }


condition:
	$a0
}