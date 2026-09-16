rule Win_Trojan_Agent_37002
{
strings:
	$a0 = { 584167656e742d312e646c6c00 }


condition:
	$a0
}