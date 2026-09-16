rule Win_Trojan_Carriers_3
{
strings:
	$a0 = { 36a800ff36aa00c706a800cb008c0eaa00b82012cd2f53b81612268a1dcd2f5b26c645020226f645 }


condition:
	$a0
}