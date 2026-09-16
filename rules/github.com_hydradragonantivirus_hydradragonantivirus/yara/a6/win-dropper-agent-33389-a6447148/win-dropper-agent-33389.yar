rule Win_Dropper_Agent_33389
{
strings:
	$a0 = { e95ba9ffffe836abffff33c05a5959648910684c8840008d85c4feffffba08000000e861b0ffff8d45e4ba03000000e854b0ffffc3 }


condition:
	$a0
}