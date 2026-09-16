rule Win_Trojan_MemoryLapse_1
{
strings:
	$a0 = { 2d030089864802b4408d960301b94301ccb80042992bc9ccb440b903008d964702c6864702e9cc }


condition:
	$a0
}