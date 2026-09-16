rule Win_Trojan_VS_11
{
strings:
	$a0 = { 0390bf5a04e8c1005250b92000b4408d165a04e8f9007302ebae5a59b80042e8ed007302eba2 }


condition:
	$a0
}