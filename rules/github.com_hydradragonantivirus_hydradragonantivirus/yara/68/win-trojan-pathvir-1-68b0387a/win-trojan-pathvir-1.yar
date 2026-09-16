rule Win_Trojan_PathVir_1
{
strings:
	$a0 = { 030181c2a9048bf28bfeac34daaae2fab90500b440cd21b9f7038b16030181c20001b440cd21 }


condition:
	$a0
}