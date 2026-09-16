rule Win_Trojan_Crypt_155
{
strings:
	$a0 = { 60e803000000eb03ebc3eb61eb5ccc??feffff9090606a40eb3c8db5??feffff8b0683f8010f844b020000c706010000008bd58b85??feffff2bd08995??feffff0195??feffff8db5????ffff01168b368bfdebc090680010000068001000006a00ff95 }


condition:
	$a0
}