rule Win_Trojan_Questo_1
{
strings:
	$a0 = { e992758f632f3d43b4734aca7d53059dea336b53b314a4167fec20b56f29852cf2 }


condition:
	$a0
}