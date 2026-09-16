rule Win_Dropper_Agent_35386
{
strings:
	$a0 = { 633a5c637261736864756d702e6c6f67 }

	$a1 = { 6e7672736f6c33322e646c6c }

	$a2 = { 0300420049004e }


condition:
	$a0 and $a1 and $a2
}