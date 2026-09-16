rule Win_Trojan_Prowler_1
{
strings:
	$a0 = { e81b00b44033d2b9bf06e8e9ffbe6000e80b00c35d81ed05008db66000561e33c08ed8fa }


condition:
	$a0
}