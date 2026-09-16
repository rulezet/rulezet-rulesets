rule Win_Trojan_GDE_2
{
strings:
	$a0 = { 011e57b8ff00509ac5069800b001509a57023600bf5a031e57bf73020e5731c0509a6d069800 }


condition:
	$a0
}