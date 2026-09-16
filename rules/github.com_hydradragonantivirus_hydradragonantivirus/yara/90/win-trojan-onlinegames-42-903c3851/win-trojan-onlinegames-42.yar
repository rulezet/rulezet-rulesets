rule Win_Trojan_Onlinegames_42
{
strings:
	$a0 = { 558bec83ec4456ff157f7943008bf08a003c22eb2d468a0684c074043c2275f5 }


condition:
	$a0
}