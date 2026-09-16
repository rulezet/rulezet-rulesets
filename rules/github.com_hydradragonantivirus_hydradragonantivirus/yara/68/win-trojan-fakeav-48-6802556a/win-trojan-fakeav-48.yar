rule Win_Trojan_Fakeav_48
{
strings:
	$a0 = { 6801407d00e801000000c3c3fb51bb4cb972aa1bb17c2f0de89d9c450db18dabef7a729c6801c882fba773715f51dc6a }


condition:
	$a0
}