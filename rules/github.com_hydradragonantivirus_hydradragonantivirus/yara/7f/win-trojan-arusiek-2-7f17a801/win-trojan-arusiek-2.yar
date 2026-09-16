rule Win_Trojan_Arusiek_2
{
strings:
	$a0 = { 4474e4505351065657521e5580fc6c74163d004b740f }


condition:
	$a0
}