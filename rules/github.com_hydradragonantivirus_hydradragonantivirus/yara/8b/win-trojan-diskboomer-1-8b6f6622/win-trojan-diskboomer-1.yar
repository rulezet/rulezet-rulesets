rule Win_Trojan_DiskBoomer_1
{
strings:
	$a0 = { 0e1f07be81028bfeac3c24740534f0aaebf6c3e9f700e8e6ffb404cd1a80fa177513b409baa102cd21b002b9ffffbb }


condition:
	$a0
}