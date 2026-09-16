rule Win_Spyware_5709_1
{
strings:
	$a0 = { 416c6572744469616c6f67[0-20]4156502e427574746f6e }

	$a1 = { 76657200ffffffff06000000686974706f70 }


condition:
	$a0 and $a1
}