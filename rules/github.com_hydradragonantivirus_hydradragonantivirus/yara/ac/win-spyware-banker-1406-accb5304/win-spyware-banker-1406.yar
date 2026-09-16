rule Win_Spyware_Banker_1406
{
strings:
	$a0 = { 1d7e9da91331d54950b8fded1e83f09e38f126b2a0cea36568bbe25483c436f2534b0ef659562b50d1e3d3d8e1186d3bf45d06e7dd796aa4d85bd85177f8fd4a166b8473 }


condition:
	$a0
}