rule Win_Trojan_Andromeda_9
{
strings:
	$a0 = { eb2053b42acd2180fa05751280fe03750db000b96400ba0100bb0001cd26be3412b430cd2183ffdd7518be83035b }


condition:
	$a0
}