rule Win_Trojan_VGEN_157
{
strings:
	$a0 = { 42cd21eb064459e803e804b9cd03be1b018bfeac3400aae2fab82135cd21891e65028c0667028cc8488ed8ac803e }


condition:
	$a0
}