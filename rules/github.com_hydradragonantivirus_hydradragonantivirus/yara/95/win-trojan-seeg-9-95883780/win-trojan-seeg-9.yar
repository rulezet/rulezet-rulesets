rule Win_Trojan_Seeg_9
{
strings:
	$a0 = { 52f7e15a2bf88b0580ec7232c003d05858e800005d81ed2102eb089033dbeb0390b7228db6 }


condition:
	$a0
}