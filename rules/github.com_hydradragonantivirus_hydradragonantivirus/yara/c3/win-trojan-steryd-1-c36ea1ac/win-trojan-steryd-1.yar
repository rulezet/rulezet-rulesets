rule Win_Trojan_Steryd_1
{
strings:
	$a0 = { 022ea34802b82435cd212e8c064a022e891e4c02b82425ba4102cd21b94100be4e02bf84fd2e8a04fec82e8805 }


condition:
	$a0
}