rule Win_Trojan_Jerusalem_41
{
strings:
	$a0 = { f2ae263805e0f98bd783c2038cc08ed88cc88ec0bb }


condition:
	$a0
}