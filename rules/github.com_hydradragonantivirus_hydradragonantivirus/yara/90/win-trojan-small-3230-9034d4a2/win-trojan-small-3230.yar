rule Win_Trojan_Small_3230
{
strings:
	$a0 = { de531d7bd72fb5c1ccef423ebe983e16be93a86d277bd9c52683d9d9ea811b6d042f1fc203731fc24399b54ede532d2c9a7f1fc2984499d2d92f3a82a9b351c3992f40cf1d3ff5c1244459d2d92f56daaa6f }


condition:
	$a0
}