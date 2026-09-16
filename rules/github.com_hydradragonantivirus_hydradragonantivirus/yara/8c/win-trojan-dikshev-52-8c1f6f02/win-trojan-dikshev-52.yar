rule Win_Trojan_Dikshev_52
{
strings:
	$a0 = { 2a2e652ab44ee80000b601cd21ba9e008bfab82e5bae75fd66c705636f6d00cd2193b440b127c3 }


condition:
	$a0
}