rule Win_Trojan_SdBot_3674
{
strings:
	$a0 = { 9d1d7f94f18821bf92ad94bb251e450deff053415ca878eea9733a5c8288d26a8297c976aee30e0897e373ccd2f7ca29ce2b5dad51f68a05cdec0534a3f54f9dd713adc978ff3c42593bcbdeacff }


condition:
	$a0
}