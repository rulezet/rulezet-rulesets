rule Win_Trojan_WereWolf_4
{
strings:
	$a0 = { ff800272f4c3e8edffc6068402b8cd21c606840281ebdf }


condition:
	$a0
}