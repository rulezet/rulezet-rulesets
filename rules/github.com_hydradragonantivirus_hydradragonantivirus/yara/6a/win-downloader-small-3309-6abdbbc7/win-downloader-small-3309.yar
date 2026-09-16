rule Win_Downloader_Small_3309
{
strings:
	$a0 = { 886a9a1256f32ebc5ef7f22a2810067f5d90c031c61b11de46c40e3674a78cfd432c2f0256a2f2cfafe8ea99d640a0bc3e1389039b2fb6c35c02 }


condition:
	$a0
}