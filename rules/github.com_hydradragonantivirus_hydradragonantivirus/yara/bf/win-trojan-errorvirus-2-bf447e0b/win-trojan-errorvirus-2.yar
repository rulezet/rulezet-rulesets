rule Win_Trojan_ErrorVirus_2
{
strings:
	$a0 = { 06b7058cdf8cc88ed88ec02da000bae90a89168f01a391018cc82d0901ba8a0689167701a37401b42acd2180fe }


condition:
	$a0
}