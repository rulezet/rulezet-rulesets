rule Win_Trojan_Subsys_6
{
strings:
	$a0 = { aac2ad3ec378ca2c39a610a8fa80da5cb6b74ac421bf994fcbf58c7886e93608b4771363be96762bbee2f6fb5c83699478d791c0647494e7a23eb1db33737d25 }


condition:
	$a0
}