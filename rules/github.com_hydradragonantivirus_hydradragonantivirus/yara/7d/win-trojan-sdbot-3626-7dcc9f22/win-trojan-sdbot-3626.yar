rule Win_Trojan_SdBot_3626
{
strings:
	$a0 = { f1d48d7787a26a7bc8e46f69b389a09a80077968c14d7a66f15c7cd11d0a41b3f1400e4bdabe53f06f90e1fcfc65c6fb67d3cde1bd68e0bb714d37b116735c280bc41c24e33e485aabe50b78897c }


condition:
	$a0
}