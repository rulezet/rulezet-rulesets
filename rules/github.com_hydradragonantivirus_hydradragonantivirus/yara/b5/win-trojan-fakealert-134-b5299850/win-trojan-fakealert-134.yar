rule Win_Trojan_Fakealert_134
{
strings:
	$a0 = { 56900fdbce9057900fdbc990893424900fdbcf906a30e9150100006633c0e913 }


condition:
	$a0
}