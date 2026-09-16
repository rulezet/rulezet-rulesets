rule Win_Spyware_Banker_2999
{
strings:
	$a0 = { bd64c5de22caffba49d6c9e3727f3e15b5657a21d35df7b60961918952ea9e521234aa8e0517758423500cc2656b8cd9fd4edf885cacea613cbecb996170f98083b8876e }


condition:
	$a0
}