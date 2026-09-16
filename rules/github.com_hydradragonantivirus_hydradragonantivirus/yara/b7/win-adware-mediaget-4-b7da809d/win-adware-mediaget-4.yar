rule Win_Adware_Mediaget_4
{
strings:
	$a0 = { 4d5a9000 }

	$a1 = { 72733e646f776e6c6f61642e6d656469616765742e636f6d2c646f776e6c6f6164322e6d656469616765742e636f6d3c2f64 }


condition:
	$a0 and $a1
}