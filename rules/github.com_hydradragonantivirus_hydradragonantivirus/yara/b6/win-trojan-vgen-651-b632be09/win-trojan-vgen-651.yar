rule Win_Trojan_VGEN_651
{
strings:
	$a0 = { b9f50380340046e2fabc0006ff06f204b430cd213c041bffc6066604ffbb6000b44acd21b452cd21268b47fe8c }


condition:
	$a0
}