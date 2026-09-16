rule Win_Trojan_Gosia_3
{
strings:
	$a0 = { c27001b001b90000b443cd2172358bd681c27001b0 }


condition:
	$a0
}