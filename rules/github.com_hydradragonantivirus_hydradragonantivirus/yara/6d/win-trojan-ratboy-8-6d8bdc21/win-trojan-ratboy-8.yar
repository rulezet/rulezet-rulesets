rule Win_Trojan_Ratboy_8
{
strings:
	$a0 = { 3fb90400ba5001cd21b43ecd21803e5301727504b44f }


condition:
	$a0
}