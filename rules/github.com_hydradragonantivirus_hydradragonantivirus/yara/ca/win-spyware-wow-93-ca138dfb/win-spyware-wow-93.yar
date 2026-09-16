rule Win_Spyware_WOW_93
{
strings:
	$a0 = { 558bec81c4dcfeffff688c5440006a006a00e8e1e3ffffe85ce6ffff68040100008d85dffeffff50a15076400050e805e4ffffc68405dffeffff00e838e6ffff8d85dffeffff50e804e4ffffe827e6ffffe88affffff }


condition:
	$a0
}