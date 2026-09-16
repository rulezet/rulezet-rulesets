rule Win_Trojan_Forever_1
{
strings:
	$a0 = { 0cc1e2048bc8b800429cff1e4400722db440b9900333d29cff1e4400721f3bc1721bb8004233 }


condition:
	$a0
}