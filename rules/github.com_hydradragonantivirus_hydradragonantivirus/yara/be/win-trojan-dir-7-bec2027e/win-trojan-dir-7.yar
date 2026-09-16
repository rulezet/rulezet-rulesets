rule Win_Trojan_Dir_7
{
strings:
	$a0 = { bc0006ff06eb0431c98ed9c506c1000521001e50b430e824 }


condition:
	$a0
}