rule Win_Trojan_HXH_1
{
strings:
	$a0 = { 1e0e1f0e078f065107b904008d362307e84805b4fecd2180fcaa7550803ec60601742b8cc82b06260501062a05 }


condition:
	$a0
}