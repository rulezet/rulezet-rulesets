rule Win_Trojan_ARCV_22
{
strings:
	$a0 = { 797acd213d595a745833c08ed88cc0488ec0a184 }


condition:
	$a0
}