rule Win_Trojan_Youth_10
{
strings:
	$a0 = { cd21eb064459df03e804b9c403be1b018bfeac3400aae2fab82135cd21891e66028c0668028cc8488ed8ac803e }


condition:
	$a0
}