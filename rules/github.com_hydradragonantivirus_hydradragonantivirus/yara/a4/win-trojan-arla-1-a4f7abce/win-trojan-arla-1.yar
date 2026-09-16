rule Win_Trojan_Arla_1
{
strings:
	$a0 = { 6e7961726c6174686f7465702d2d3e }

	$a1 = { 6e313d2f64636373656e64246e69636b[0-28]6d79646f6f6d2e68746d }


condition:
	$a0 and $a1
}