rule Win_Trojan_Delf_893
{
strings:
	$a0 = { 6a00e8aec2f6ffeb33a16c8a4a008b00e8c8a2f6ff8bc8bafcab4900b801000080e833dffbffe86aa300006a00e883c2f6ffeb088b45fc8b08ff51f0 }


condition:
	$a0
}