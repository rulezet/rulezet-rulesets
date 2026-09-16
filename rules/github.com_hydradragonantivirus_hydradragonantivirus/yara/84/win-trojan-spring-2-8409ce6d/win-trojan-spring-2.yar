rule Win_Trojan_Spring_2
{
strings:
	$a0 = { 8ed8b89696bb84009cff1f3d97967468b462cd212bff }


condition:
	$a0
}