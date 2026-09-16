rule Win_Trojan_Casino_2
{
strings:
	$a0 = { a13d00050306bbfeff2bd8891e0306bb }


condition:
	$a0
}