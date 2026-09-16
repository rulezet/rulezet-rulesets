rule Win_Trojan_Haldeman_2
{
strings:
	$a0 = { 40b904008d960202cd21fe860602b802422bc999cd21b440b966028d960600cd21b43ecd21c3 }


condition:
	$a0
}