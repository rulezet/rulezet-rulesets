rule Win_Trojan_Kontragapi_1
{
strings:
	$a0 = { 744622208a2080e420a020208a2080e420a020208a2080e420a020208a2080e420a02020e905ff }


condition:
	$a0
}