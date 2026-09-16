rule Win_Trojan_Small_142
{
strings:
	$a0 = { 03f78b5cfe03df07060e03ff26833d007516b97800f3a4be840026a526a526c744fc3e02268c44fe07ffe3b4 }


condition:
	$a0
}