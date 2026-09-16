rule Win_Trojan_Argentina_5
{
strings:
	$a0 = { 81e9e105b4facd21b82135cd21891e1a }


condition:
	$a0
}