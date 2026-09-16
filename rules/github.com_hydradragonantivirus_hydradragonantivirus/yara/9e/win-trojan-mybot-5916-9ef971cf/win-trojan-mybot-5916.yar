rule Win_Trojan_Mybot_5916
{
strings:
	$a0 = { 3b9d5323a77346d6e13f3fe31bde5c6a829cf67ea6765e98039f1a0755e70fd3cd860f98e8d869c92e1ec1c6cdd61f72639338ec68646d }


condition:
	$a0
}