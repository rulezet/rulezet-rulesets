rule Win_Trojan_Snake_4
{
strings:
	$a0 = { 1e00d1e8d1e8d1e8d1e80514003e01861d035bb440b927008d960000cd218db627008dbed903b9 }


condition:
	$a0
}