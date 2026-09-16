rule Win_Trojan_Bishop_1
{
strings:
	$a0 = { 0181fdb4b380f9b0ffd13cb2b96c0181ff4c9990ffe1011c37526d88a3bed9f40f2a45607b96b1cce7021d38536e }


condition:
	$a0
}