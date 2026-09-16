rule Win_Trojan_Laroux_74
{
strings:
	$a0 = { 696e666563746564206279 }

	$a1 = { 4e4547532e584c5321636865636b5f66696c6573 }


condition:
	$a0 and $a1
}