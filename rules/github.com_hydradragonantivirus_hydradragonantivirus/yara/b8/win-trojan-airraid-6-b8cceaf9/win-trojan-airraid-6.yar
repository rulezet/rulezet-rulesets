rule Win_Trojan_AirRaid_6
{
strings:
	$a0 = { b94f9f90d79024b24048368bf9f81dda59cc5559d3cf90b9f5aeb445cd21fd40badbabf82be89826c706931acd203e }


condition:
	$a0
}