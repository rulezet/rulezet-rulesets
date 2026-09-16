rule Win_Trojan_RMNS_1
{
strings:
	$a0 = { ee0601bf840101f78a05a20001478b05a30101b8bb4bcd213db4bb7503e957008cc8488ec026a000003c5a74050e }


condition:
	$a0
}