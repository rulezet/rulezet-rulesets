rule Win_Spyware_Banker_1400
{
strings:
	$a0 = { 8a001220cbd8d32a71f3fb57528c339afe839338c23ef717da2080c17e5fda3b3efeb25296a05c3dc13462d5f0eb80c8a48cb25a890f0973d71b4e8e78d138b03801ee0a }


condition:
	$a0
}