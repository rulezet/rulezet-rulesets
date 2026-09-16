rule Win_Trojan_Helios_2
{
strings:
	$a0 = { 2b014a06fbfdff303230343348656c696f535f430b656e742607ffffff6fcc4d05a10ab0044d231c4a8b4219af5189a912db7008b715f0ee420cffffffbdc4ab6c498eab413a4fad }


condition:
	$a0
}