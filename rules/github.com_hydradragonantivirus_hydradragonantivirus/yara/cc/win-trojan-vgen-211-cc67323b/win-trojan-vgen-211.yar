rule Win_Trojan_VGEN_211
{
strings:
	$a0 = { 90e98b0190902eff1e8c009c3cff742d909050561e2e8b3639022e8e1e3b02803cff750383c6078a4417241f90 }


condition:
	$a0
}