rule Win_Trojan_Peed_225
{
strings:
	$a0 = { b826250300732effd25dffe05589e551418b7d0c66abc1c80890c1c80866ab83 }


condition:
	$a0
}