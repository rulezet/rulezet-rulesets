rule Win_Trojan_Small_140
{
strings:
	$a0 = { 8b75fe03f78b5cfe03df07060e03ff26382d7515b174f3a4be840026a526a526c744fc3c02268c44fe07ffe3b44233 }


condition:
	$a0
}