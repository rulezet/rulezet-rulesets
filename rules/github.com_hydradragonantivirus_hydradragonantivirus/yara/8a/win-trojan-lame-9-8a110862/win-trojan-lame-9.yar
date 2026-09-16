rule Win_Trojan_Lame_9
{
strings:
	$a0 = { 0100b44eba3801cd217303e92600b8023dba9e00cd2193b440b96200ba0001cd21fe064101 }


condition:
	$a0
}