rule Win_Trojan_Requires_3
{
strings:
	$a0 = { b8023dcd218bd81e8ccb8ed8b80057cd215152803c65740c }


condition:
	$a0
}