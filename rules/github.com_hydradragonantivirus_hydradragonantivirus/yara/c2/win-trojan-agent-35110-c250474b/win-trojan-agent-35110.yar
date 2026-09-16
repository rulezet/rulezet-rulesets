rule Win_Trojan_Agent_35110
{
strings:
	$a0 = { 7d8a5f6a446ec4367c96e56e2e5efdf210184e2280b14d7900dfc04d85aad47ecba4c13ee2c4c4d8a59c4f78fcac089a0b4b0ecfcb912fe2e71171ef }


condition:
	$a0
}