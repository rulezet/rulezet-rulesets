rule Win_Trojan_XRes_1
{
strings:
	$a0 = { 0190fcf3a48ed8ba3802b82125cd21071f582eff2e4b }


condition:
	$a0
}