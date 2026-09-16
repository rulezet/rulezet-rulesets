rule Win_Trojan_Hupigon_170
{
strings:
	$a0 = { a158584a008b00e8962ff6ff508d55e433c0e8cb0cf6ff8b45e4e8832ff6ff50e8a552f6ff85c00f840202000068b0254a006aff6a00e8e74ef6ff8bd885db741ee82c50f6ff }


condition:
	$a0
}