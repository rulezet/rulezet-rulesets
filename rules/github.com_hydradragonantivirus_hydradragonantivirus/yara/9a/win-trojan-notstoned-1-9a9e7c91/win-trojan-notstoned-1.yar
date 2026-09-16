rule Win_Trojan_NotStoned_1
{
strings:
	$a0 = { c60c05bf0001b90600f3a45eb8feffcd133d555575080e0e1f07ffa44205b42acd2181f9ca07 }


condition:
	$a0
}