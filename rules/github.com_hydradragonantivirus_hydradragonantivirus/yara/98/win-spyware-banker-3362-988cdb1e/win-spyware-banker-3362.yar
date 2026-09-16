rule Win_Spyware_Banker_3362
{
strings:
	$a0 = { c73f705438f4ab63d1bbbd411c15e66d7123237aa6364086708d3b3980f0c99aea18d2f2e066acac8b6aa5938bcea1539c41a67b8284803f8d0837cbbec5fcc779fc2daa5695704a63 }


condition:
	$a0
}