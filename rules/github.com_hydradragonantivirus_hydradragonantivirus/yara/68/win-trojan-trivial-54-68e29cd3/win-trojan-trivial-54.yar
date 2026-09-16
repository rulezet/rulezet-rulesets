rule Win_Trojan_Trivial_54
{
strings:
	$a0 = { 0510008ed8b430cd213c007448b42fcd21891e70008c067200ba7400b41acd21b44eb90100ba5b00cd2172298026 }


condition:
	$a0
}