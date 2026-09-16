rule Win_Trojan_Hi_6
{
strings:
	$a0 = { 8c06ad02ba8000b82125cd210e1f8ccb3e2b9ea6 }


condition:
	$a0
}