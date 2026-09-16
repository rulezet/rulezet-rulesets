rule Win_Trojan_Subsys_21
{
strings:
	$a0 = { 0fc3f00a20476eefb30ceccffbe7fd6917f8a8562a8eba9153ade5905d07dbc820af980654079dacef0fd7d50fe2f2f7 }


condition:
	$a0
}