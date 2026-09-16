rule Win_Trojan_Hupigon_686
{
strings:
	$a0 = { f055b9a3d7b86d0bbfe498f60c88d453140da2e2d7144f071bccf43fc15f0ed9dec0f75959cf149805b7e406a1cdde33387fb5034ac1da165608cb7bdbe4a622eb }


condition:
	$a0
}