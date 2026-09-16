rule Win_Trojan_Agent_34289
{
strings:
	$a0 = { 8d45bc50b101ba882c1413a1b0461413e88ef3ffff8b55bcb8b0461413e839ebffffb8b0461413e887edffffe832f4ffff33c05a595964891068442b14138d }


condition:
	$a0
}