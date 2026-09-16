rule Win_Trojan_Gen_107
{
strings:
	$a0 = { c5740e50fecc3d004a740a582eff2e8102f9b001ff5e34363146ff8dbe00ff16578dbe5ce81657b8a016508dbefcfe16579a25 }


condition:
	$a0
}