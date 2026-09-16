rule Win_Trojan_Momibot_6
{
strings:
	$a0 = { 85c581f61caf25f966bbde68c1c21481deedce9c2e66bb450b66bb388a4e8b04240f8212000000f7da730ef7da81f3d9dac928beff2f1d6e43 }


condition:
	$a0
}