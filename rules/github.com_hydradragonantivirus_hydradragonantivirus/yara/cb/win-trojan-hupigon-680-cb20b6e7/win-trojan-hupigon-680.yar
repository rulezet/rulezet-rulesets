rule Win_Trojan_Hupigon_680
{
strings:
	$a0 = { 2d767e3232a25cbb4a82a9259b1613c8ae31d0e1ff32ca768ddd4e6b03fc6af27c9fedaf4ca47581ec6338813be13e1bd7595475085e2874867ab66895a725910b }


condition:
	$a0
}