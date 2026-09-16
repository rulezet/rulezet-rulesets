rule Win_Trojan_Eddy_4
{
strings:
	$a0 = { 028a4414345288441233d2b92405b440cd21b000e87600ba2805b91800b440cd21e90eff32c0 }


condition:
	$a0
}