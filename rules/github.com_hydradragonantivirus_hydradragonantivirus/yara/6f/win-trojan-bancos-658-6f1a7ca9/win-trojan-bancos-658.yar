rule Win_Trojan_Bancos_658
{
strings:
	$a0 = { 46f1fa80c3d51f1dc3ec9bc038aaeb2f17da44105c585d5c54ae346f1e8a15d2e9608e86a9646eeaf24efe38c5aa75e56b2e79512135f303f493066b97d7bd2195e61390 }


condition:
	$a0
}