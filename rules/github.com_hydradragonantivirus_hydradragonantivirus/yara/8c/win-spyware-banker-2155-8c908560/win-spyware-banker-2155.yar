rule Win_Spyware_Banker_2155
{
strings:
	$a0 = { 12086d6ada7f675a98153dc8fb8c0d8736f07f1f5343210f1673b97ae342bb4c86b240816a29deedc0434ddd1b00100afb3fa4cb152bbd8dcfc7d56ecbf78aba950c4a8a9db2cae301a58126df53 }


condition:
	$a0
}