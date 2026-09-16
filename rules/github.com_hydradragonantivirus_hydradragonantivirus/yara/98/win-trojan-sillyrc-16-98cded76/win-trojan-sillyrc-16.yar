rule Win_Trojan_SillyRC_16
{
strings:
	$a0 = { 06cb02e9a3cc022de7003944017429b440b9e700bae001cd2126896d1526896d17b440b90300ba }


condition:
	$a0
}