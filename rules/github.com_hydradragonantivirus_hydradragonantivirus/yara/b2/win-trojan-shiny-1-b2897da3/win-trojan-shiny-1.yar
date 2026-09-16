rule Win_Trojan_Shiny_1
{
strings:
	$a0 = { b0e9aab8030091ab51b440b9a60399e88200b8004233c999cd21b44059baad03e87100b80157 }


condition:
	$a0
}