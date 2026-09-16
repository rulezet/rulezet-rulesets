rule Win_Trojan_Ms_1
{
strings:
	$a0 = { 2d0301b104d3e88cc903c18ed82ea12c008ec08b3ef004b050fcb9fffff2ae26813d415475f426807d024875ed83c7 }


condition:
	$a0
}