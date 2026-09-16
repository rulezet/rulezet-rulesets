rule Win_Trojan_LastBug_1
{
strings:
	$a0 = { 96005589e581ec000231c0a32403a14000a326038dbe00ff165731c0509ad60c9600bf24021e57b8ff00509a4a }


condition:
	$a0
}