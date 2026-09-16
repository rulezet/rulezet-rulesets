rule Win_Dropper_Agent_35439
{
strings:
	$a0 = { 558becb822e218f9bb4487cc4a50e800000000582da81a0000b96d1a0000ba }

	$a1 = { 471742353d716366526f }


condition:
	$a0 and $a1
}