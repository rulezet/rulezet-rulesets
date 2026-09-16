rule Win_Trojan_Andromeda_13
{
strings:
	$a0 = { 40ba0001b93a03cd212ea117042ea315045b53b8004233c933d2cd215b53b440baa304b90500cd }


condition:
	$a0
}