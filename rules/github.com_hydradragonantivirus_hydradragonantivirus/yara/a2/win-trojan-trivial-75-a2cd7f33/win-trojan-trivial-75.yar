rule Win_Trojan_Trivial_75
{
strings:
	$a0 = { b44eb90000ba5c01cd217232b8023dba9e00cd2189c3b43fb90200ba8501cd21813e850190907420b80042b90000 }


condition:
	$a0
}