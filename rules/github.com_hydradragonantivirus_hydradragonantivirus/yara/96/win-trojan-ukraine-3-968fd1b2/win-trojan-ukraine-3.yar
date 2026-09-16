rule Win_Trojan_Ukraine_3
{
strings:
	$a0 = { d0ca81c23b24d0c201d381ea12408bec82c24e31d382c2b9d1cad0c281f2cf18fa31d381c2cd9901d3d0ca82c29e }


condition:
	$a0
}