rule anti_debug__ICECream_detection__Windows_95____8_byt_26_
{
strings:
	$a0 = { 83c0088b1883c0108b0025ffff000081e3ffff000029d883f81e }

condition:
	$a0
}