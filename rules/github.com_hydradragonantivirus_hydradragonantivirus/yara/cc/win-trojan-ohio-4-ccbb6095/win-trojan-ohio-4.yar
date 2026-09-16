rule Win_Trojan_Ohio_4
{
strings:
	$a0 = { 04005132e4cd13720d33d2b92128bb }


condition:
	$a0
}