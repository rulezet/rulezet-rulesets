rule Win_Trojan__0385_0004_000_1
{
strings:
	$a0 = { 81c51203e88805b90012baf112b440cd21e8f704b440b90300ba290bcd21e9d700803e820b }


condition:
	$a0
}