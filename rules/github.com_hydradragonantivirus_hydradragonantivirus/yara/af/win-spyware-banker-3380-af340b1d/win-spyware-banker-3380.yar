rule Win_Spyware_Banker_3380
{
strings:
	$a0 = { 2d1bc5ceca19adc205cbfdfd3a693b8a6cb051d437fb42717958a924496342a11c9455d704f6d167be8b0245db1308b1259e0674cd1287a0c70f701f5e3af3eb3cc45fbaf3d5 }


condition:
	$a0
}