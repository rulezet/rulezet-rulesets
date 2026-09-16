rule Win_Trojan_SillyOC_45
{
strings:
	$a0 = { 8bf6b44eb92700ba????cd2172[5-15]b42acd2180fa0375??80fe0a74 }


condition:
	$a0
}