rule Win_Trojan_Inject_50
{
strings:
	$a0 = { 6801504000e801000000c3c3ca14518310cc89f1ae08e99bacb8b01d4a3349b6f2f1bf5f13c73d38 }


condition:
	$a0
}