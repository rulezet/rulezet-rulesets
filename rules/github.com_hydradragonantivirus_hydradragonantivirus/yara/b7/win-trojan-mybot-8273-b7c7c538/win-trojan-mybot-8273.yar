rule Win_Trojan_Mybot_8273
{
strings:
	$a0 = { 8fdfae0a6a1d5fc55e8533b9954cb46cd616e9bcea4ee8e689018eb9681322782cdc5a3ff19e6f58ac7a2e8946ae1714430f599a63086571e61eb0eff3de08b85810977feda0 }


condition:
	$a0
}