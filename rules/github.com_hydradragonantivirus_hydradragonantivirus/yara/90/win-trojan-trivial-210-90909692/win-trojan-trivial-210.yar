rule Win_Trojan_Trivial_210
{
strings:
	$a0 = { 2301b44ecd21b8023dba9e00cd218bd8b92700ba0001b440cd21b43ecd21b44febe2 }


condition:
	$a0
}