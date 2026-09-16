rule Win_Trojan_VGEN_256
{
strings:
	$a0 = { 1917ba2e053bc473678bc42d440325f0ff8bf8b9a200be7c01fcf3a58bd8b104d3eb8cd903d95333db53cb0301d322 }


condition:
	$a0
}