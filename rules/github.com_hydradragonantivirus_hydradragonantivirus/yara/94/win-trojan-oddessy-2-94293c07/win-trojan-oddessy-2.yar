rule Win_Trojan_Oddessy_2
{
strings:
	$a0 = { 03cd21b9d107ba6e02b42bcd21ba4803b90200b44ecd21b44fba4803cd21b443ba9e00b000cd21b100b44390 }


condition:
	$a0
}