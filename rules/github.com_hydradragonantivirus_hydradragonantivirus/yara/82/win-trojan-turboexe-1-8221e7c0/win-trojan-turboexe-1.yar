rule Win_Trojan_TurboExe_1
{
strings:
	$a0 = { 5d83ed031e06501e06b82135cd2126807fff0d077503eb7490b448bbffffcd2183fb4173108cd8488ed88b1e03 }


condition:
	$a0
}