rule Win_Trojan_NewYear_1
{
strings:
	$a0 = { 5500a34400e86f017216be3800bf1a00b91600e8e702ba1800b91c00b440cd218b161000 }


condition:
	$a0
}