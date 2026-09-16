rule Win_Trojan_Mybot_5558
{
strings:
	$a0 = { dee4bcf4774ec6ff6dcd39c1f18b0129dd0e3818894629ef91d670d8f4de1ca9830fc6fecf04a44e56fea9d4f50d3c6e8ec9d2fcdbfda81713e377ab6f203aeb999e2e048dc8 }


condition:
	$a0
}