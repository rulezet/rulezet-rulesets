rule Win_Trojan_Vgen_90
{
strings:
	$a0 = { 5e83ee03b82135cd218cc12bc08ec0b81516263b06ec03740e26a3ec0326891ee80326890eea030e1f0e07b904 }


condition:
	$a0
}