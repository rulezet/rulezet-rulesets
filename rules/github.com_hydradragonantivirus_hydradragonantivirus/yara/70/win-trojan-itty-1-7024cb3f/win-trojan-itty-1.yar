rule Win_Trojan_Itty_1
{
strings:
	$a0 = { 0fffcd213d01017415b44eb92700ba8c01cd217215 }


condition:
	$a0
}