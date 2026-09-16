rule Win_Trojan_Alladin_1
{
strings:
	$a0 = { dca6d4501983a93818b1a15650a4b5a12a7915eb6c80bf5b1f25a11e3ca792612f795d04041f81a1 }


condition:
	$a0
}