rule TrojanSirefefZerroAccessPluginModuleZooCliccer
{
	meta:
		Description  = "Trojan.ZooClicker.sm"
		ThreatLevel  = "5"

	strings:
		$ = "%s\\00000001.@" ascii wide                                                                                                                                                                                                                                                                                                                                                                   
		$ = "z00clicker3"  ascii wide  
		$ = "z00clicker"  ascii wide

	condition:
		any of them
}