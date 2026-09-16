rule Win_Trojan_DualGTM_1
{
strings:
	$a0 = { 6e01b92e059c2eff1e2e01b440ba9c06b96e009c2eff1e2e01b801578b0e2a018b162c0180 }


condition:
	$a0
}