rule Win_Trojan_G_15
{
strings:
	$a0 = { e800005d81ed13001e06b84144cd213d535074508cd8488ed8832e03004f832e12004fa112008ed8 }


condition:
	$a0
}