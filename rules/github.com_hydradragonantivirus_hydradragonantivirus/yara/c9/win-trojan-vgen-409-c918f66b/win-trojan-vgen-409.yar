rule Win_Trojan_VGEN_409
{
strings:
	$a0 = { 1e008ec0bf0600be3e008bee8cc88ed8b9e000fcf3a5ea23001e00ba2000bb00003bd974258cd88ec08bfd8bcbac }


condition:
	$a0
}