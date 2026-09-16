rule Win_Adware_Downware_2
{
strings:
	$a0 = { 687474703a2f2f69772e616e74746869732e636f6d2f7465726d732f }


condition:
	$a0
}