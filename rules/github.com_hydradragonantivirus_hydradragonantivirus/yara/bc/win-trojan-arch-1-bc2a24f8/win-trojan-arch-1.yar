rule Win_Trojan_Arch_1
{
strings:
	$a0 = { 7b005589e531c09acd027b009aeb067b0009c07f03e9aa00bf58011e57bfdc020e5731c0509a70067b009add05 }


condition:
	$a0
}