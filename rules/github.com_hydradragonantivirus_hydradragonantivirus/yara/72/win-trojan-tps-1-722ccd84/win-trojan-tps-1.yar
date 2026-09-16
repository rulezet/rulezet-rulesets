rule Win_Trojan_Tps_1
{
strings:
	$a0 = { 90b425b01cba0501cd21b80031ba1400cd21b402cd1a8ac15150240f0430a2130258b104d2e8240f0430a2120259 }


condition:
	$a0
}