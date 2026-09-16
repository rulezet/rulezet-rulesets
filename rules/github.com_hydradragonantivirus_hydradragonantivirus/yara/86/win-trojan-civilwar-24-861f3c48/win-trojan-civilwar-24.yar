rule Win_Trojan_CivilWar_24
{
strings:
	$a0 = { 5d81ed0901bf00018db65d03b90600f3a4b4a0cd213d080074608cc8488ed8803e00005a754ea103002d0002a3 }


condition:
	$a0
}