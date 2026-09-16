rule Win_Trojan_Trojan_297
{
strings:
	$a0 = { 1e57b8ff00509ac3069800b001509a57023600bf5a031e57bf73020e5731c0509a6b06 }


condition:
	$a0
}