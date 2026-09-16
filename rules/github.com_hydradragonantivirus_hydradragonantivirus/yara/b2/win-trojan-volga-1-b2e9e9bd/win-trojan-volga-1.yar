rule Win_Trojan_Volga_1
{
strings:
	$a0 = { 02fcf3a6741883fe05770bb80103e81600e856ff7208b8010333dbe847ff }


condition:
	$a0
}