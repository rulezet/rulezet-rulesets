rule Win_Trojan_K_5
{
strings:
	$a0 = { 2e2800802eff061500902e813e15004b1175eb90 }


condition:
	$a0
}