rule Win_Trojan_Khizhnjak_9
{
strings:
	$a0 = { 1eaf02ba1001b9a301cd21b800428b1eaf02b90000ba0000cd218b1ea00283eb03891eaa02 }


condition:
	$a0
}