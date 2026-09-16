rule Win_Spyware_Banker_176
{
strings:
	$a0 = { 1669dd42486931606f8f3e1a9ab2ed11[0-5]719c786b78447066360ee4[0-9]5eac2ffebd8659c99d244464f324[0-5]3a1b47137e }


condition:
	$a0
}