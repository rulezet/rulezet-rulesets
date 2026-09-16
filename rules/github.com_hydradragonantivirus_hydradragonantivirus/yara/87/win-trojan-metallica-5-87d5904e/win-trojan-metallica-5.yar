rule Win_Trojan_Metallica_5
{
strings:
	$a0 = { 06e101a39003ba0002b9f401b440cd21722433c933d2b80042cd217219bae001b91800b440cd21 }


condition:
	$a0
}