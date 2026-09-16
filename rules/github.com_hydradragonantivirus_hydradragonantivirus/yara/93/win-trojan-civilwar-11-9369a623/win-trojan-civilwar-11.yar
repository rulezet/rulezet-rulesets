rule Win_Trojan_CivilWar_11
{
strings:
	$a0 = { ed0901bf00018db6a603b90600f3a4b4a0cd213d0100745b8cc8488ed8803e00005a7547 }


condition:
	$a0
}