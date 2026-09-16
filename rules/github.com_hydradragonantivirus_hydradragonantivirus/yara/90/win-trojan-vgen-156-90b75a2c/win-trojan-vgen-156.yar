rule Win_Trojan_VGEN_156
{
strings:
	$a0 = { 9942cd21eb064459db03e804b9c003be1b018bfeac3400aae2fab82135cd21891e65028c0667028cc8488ed8ac803e }


condition:
	$a0
}