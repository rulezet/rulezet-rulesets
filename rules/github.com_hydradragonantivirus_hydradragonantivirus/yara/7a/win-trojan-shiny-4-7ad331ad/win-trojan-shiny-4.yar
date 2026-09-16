rule Win_Trojan_Shiny_4
{
strings:
	$a0 = { 743480fc12742f3d004b74cb2efe0e9e03804e07 }


condition:
	$a0
}