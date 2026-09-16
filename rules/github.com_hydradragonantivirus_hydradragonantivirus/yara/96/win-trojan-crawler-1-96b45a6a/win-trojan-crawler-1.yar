rule Win_Trojan_Crawler_1
{
strings:
	$a0 = { 0a058d1ef204e80b02e29c0b88b4ac09bdba06a1b5c5afb2213fc82b0359bd2e208793a306c724be2ac7240c56be1f }


condition:
	$a0
}