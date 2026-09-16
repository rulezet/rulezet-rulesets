rule Win_Trojan_Andromeda_16
{
strings:
	$a0 = { e800005b83eb2053b42acd2180fa05751280fe03750db000b96400ba0100bb0001cd26be3412b430cd2183ffdd7518beb7035b5381eb030103f3bf0001b9 }


condition:
	$a0
}