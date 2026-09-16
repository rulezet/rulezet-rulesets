rule Win_Trojan_Tijuana_1
{
strings:
	$a0 = { 13045756485648a31304b106fcd3e08ec08b454c898487008b454e89848900b9be01f3a406b18d }


condition:
	$a0
}