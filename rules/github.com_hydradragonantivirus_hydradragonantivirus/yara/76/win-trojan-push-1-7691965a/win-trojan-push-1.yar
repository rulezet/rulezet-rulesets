rule Win_Trojan_Push_1
{
strings:
	$a0 = { 021e579a290900019a0e020001b8dc05509a9e029e00bf86021e57bf9d020e5731c0509af109 }


condition:
	$a0
}