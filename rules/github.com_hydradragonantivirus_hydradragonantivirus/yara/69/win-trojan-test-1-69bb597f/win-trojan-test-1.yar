rule Win_Trojan_Test_1
{
strings:
	$a0 = { 81eb00008beb3e8a96bd03fec23e8896bd03ba0001bbe201be000003f5bfe00303fdb84000e82a008bc7bfe00303 }


condition:
	$a0
}