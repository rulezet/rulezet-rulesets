rule Win_Trojan_SeaStorm_6
{
strings:
	$a0 = { 909087d987cab9455987cb90909392cd16b9ba01bb34002e8107000083c30283e90175f3 }


condition:
	$a0
}