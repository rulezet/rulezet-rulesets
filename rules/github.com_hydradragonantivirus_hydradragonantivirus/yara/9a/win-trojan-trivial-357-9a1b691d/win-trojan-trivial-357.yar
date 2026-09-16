rule Win_Trojan_Trivial_357
{
strings:
	$a0 = { 1aba5401cd21b44eba4e01b90200cd217306b44fcd217219b8023dba7201cd2193b440b94e00ba0001cd21b43ecd21ebe1b42acd2180fe01740a80fe067405 }


condition:
	$a0
}