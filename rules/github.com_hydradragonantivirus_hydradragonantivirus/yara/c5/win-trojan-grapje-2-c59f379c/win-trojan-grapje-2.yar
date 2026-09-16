rule Win_Trojan_Grapje_2
{
strings:
	$a0 = { 400033dbc687d9010043e2f8b44732d28d36d901cd215a }


condition:
	$a0
}