rule Win_Trojan_Greemlin_1
{
strings:
	$a0 = { 95fc5b2eff07b8aad5cd213d032a745f }


condition:
	$a0
}