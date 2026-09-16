rule Win_Trojan_Eumel_27
{
strings:
	$a0 = { 555d8d762490b801faba4559cd16e80200eb108a96bf01b99b018bfeac32c2aae2fac38db68c01bf0001fca4a506b8 }


condition:
	$a0
}