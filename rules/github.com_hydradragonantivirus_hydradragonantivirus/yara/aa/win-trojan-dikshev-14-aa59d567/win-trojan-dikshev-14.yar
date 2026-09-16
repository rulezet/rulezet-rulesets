rule Win_Trojan_Dikshev_14
{
strings:
	$a0 = { 652abf9e0091b44e8bd6cd217301c38bd7b82e5bae75fd66c705636f6d20cd2172ec93b440b1 }


condition:
	$a0
}