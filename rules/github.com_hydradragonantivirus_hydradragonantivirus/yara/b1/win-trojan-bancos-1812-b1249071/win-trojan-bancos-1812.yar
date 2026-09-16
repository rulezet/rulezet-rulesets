rule Win_Trojan_Bancos_1812
{
strings:
	$a0 = { 6d77f7ac689d095b2a97e3094b4fe961763e06582d3f3def88422d2feb26d8fde09d406fc374bb3a4db7e0d72a2510f13f520133aac6930d8fa28111d64bebd137d14e8652b0 }


condition:
	$a0
}