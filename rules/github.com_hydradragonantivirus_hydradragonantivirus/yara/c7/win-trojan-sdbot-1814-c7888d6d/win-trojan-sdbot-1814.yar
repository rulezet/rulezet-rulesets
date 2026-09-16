rule Win_Trojan_SdBot_1814
{
strings:
	$a0 = { c58a9c4733e19f1d3ed36eef5b65c7f247ffef524973143fe7f60cdaa01640fd5f4441406a6f7fd9bc29b06aecd59f37d5dbd8dfb5e4705363be861b4c1ed620 }


condition:
	$a0
}