rule Win_Trojan_Boing_1
{
strings:
	$a0 = { fa47f0af02aff836778e37faca1bfa16b9af778e371a35ae173e173d02aeed9fffdf778e0e91778e }


condition:
	$a0
}