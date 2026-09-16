rule Win_Trojan_Onkelz_1
{
strings:
	$a0 = { 5ed1ea5a5de394a6e5cd5da0aff8e2b6a6b415a3e81ce694a6e5cd5d917de45c1eb41f5ce81ce55f }


condition:
	$a0
}