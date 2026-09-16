rule Win_Trojan_VGEN_79
{
strings:
	$a0 = { ba5c073bc473678bc42d440325f0ff8bf8b9a200be7c01fcf3a58bd8b104d3eb8cd903d95333db53cb0d01416e }


condition:
	$a0
}