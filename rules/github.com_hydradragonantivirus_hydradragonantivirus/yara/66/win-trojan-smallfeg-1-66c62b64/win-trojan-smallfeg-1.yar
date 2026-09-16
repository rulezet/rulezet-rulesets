rule Win_Trojan_Smallfeg_1
{
strings:
	$a0 = { 474554[0-4]485454502f312e310b00416363657074[0-140]6a7570652e646c6c }


condition:
	$a0
}