rule Win_Dropper_StealthBat_1
{
strings:
	$a0 = { 636f6d706966b3d9c83f736372297c3b513b4f3bcc0ccb664d3b4bdf2cff73b4b3b4ad4e740c7c262d6708be37732e2a2a2a004f203e818508b8e31d61910d41 }


condition:
	$a0
}