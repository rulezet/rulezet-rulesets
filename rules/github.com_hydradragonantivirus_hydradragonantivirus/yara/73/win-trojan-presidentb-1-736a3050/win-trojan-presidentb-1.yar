rule Win_Trojan_PresidentB_1
{
strings:
	$a0 = { c40583c61946b1172ed20c2e8034154875f381eedd05567f8cc2d60aac578a8bb9b98a8a8ad655926c1a14757530 }


condition:
	$a0
}