rule Win_Trojan_Rabbit_2
{
strings:
	$a0 = { c08ed88ed0bc007ccd1248a31304b106d3e08ec0a14c00a3aa7da14e00a3ac7dc7064c0084008c064e00fcb90002be }


condition:
	$a0
}