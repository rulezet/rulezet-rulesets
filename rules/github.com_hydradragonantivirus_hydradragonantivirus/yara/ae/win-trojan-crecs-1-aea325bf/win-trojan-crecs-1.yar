rule Win_Trojan_Crecs_1
{
strings:
	$a0 = { b8addecd213d43537475b82135cd212e891e????2e8c06????8ccd8bc5488ed833ff875d032ea1 }


condition:
	$a0
}