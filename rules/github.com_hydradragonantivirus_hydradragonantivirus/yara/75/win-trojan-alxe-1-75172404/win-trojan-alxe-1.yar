rule Win_Trojan_Alxe_1
{
strings:
	$a0 = { 81eef4002e8984a7002e899ca9002e898cab002e8994ad001e8cc88ed8ff7414ff7416ff740eff7410561e07 }


condition:
	$a0
}