rule Win_Dropper_Agent_33943
{
strings:
	$a0 = { a37c6614138d4dd8ba884d1413b8a84d1413e823edffff8b45d8e81fe7ffff50a17c66141350e8dfebffff }


condition:
	$a0
}