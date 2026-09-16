rule Win_Trojan_Gen_160
{
strings:
	$a0 = { 0e579a5f07ac00bf50011e57b8ff00509afa06ac00bf50011e57b8020050bf16231e579a42 }


condition:
	$a0
}