rule Win_Trojan_VGEN_383
{
strings:
	$a0 = { 33c08ed08ed88ec0bc007cfbb106a11304d3e02de0078ec033f68bfeb9003ff3a506b8647c50cb0e1fbb00628a163a }


condition:
	$a0
}