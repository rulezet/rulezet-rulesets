rule Win_Spyware_4732_1
{
strings:
	$a0 = { 575783c404890424566aff5e03c65eeb }


condition:
	$a0
}