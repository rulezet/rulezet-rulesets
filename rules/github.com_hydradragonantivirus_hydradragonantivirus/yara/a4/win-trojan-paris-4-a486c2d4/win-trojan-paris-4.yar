rule Win_Trojan_Paris_4
{
strings:
	$a0 = { 8d16a0028d3686028b1ccd218d36b0028904 }


condition:
	$a0
}