rule Win_Trojan_Dutch_Tiny_9
{
strings:
	$a0 = { 8bfe03740156a5a45e8d5450b44e3db44fcd217236b43ee82200b43f8bd6cd21803ce974eab8024233c999cd218944 }


condition:
	$a0
}