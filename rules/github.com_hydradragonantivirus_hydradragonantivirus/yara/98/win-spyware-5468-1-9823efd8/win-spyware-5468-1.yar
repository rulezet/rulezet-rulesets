rule Win_Spyware_5468_1
{
strings:
	$a0 = { 57890424565683c40489142451505981f1104d46508bc159908bd668fa5ccc1a }


condition:
	$a0
}