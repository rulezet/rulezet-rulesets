rule Win_Dropper_Agent_35800
{
strings:
	$a0 = { e836ecffffb8a09b4000ba3c574000e827ecffffb8a09b4000bad8574000e818ecffffb8 }


condition:
	$a0
}