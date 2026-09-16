rule Win_Downloader_Delf_98
{
strings:
	$a0 = { e4166485849c26e4cbf2330eb5e4b12f63bb8cccff9f0d70616e6b6d796d6f6e6b6579e72a5b060c5b004d554ef68d400b041b4a685b8e457603a81a1780109403ffff6fa5b82fcbccc8c9d7 }


condition:
	$a0
}