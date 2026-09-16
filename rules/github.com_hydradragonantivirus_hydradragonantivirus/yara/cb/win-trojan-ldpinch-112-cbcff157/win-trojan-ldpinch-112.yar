rule Win_Trojan_LdPinch_112
{
strings:
	$a0 = { 59a9423bba1f1f2dc691e3f50bdd9366fb514841db9efa4adf07caa0fd4cc6721b27496a209a9360fbe8a925a40c47d9226d3cd23c5cb9cf00bf5331cebf869f544ba51c80814ae684e7a96d2c48f371 }


condition:
	$a0
}