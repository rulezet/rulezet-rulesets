rule Win_Downloader_W32_87
{
strings:
	$a0 = { c4453bab914ed010425a956e2270fcdc3fe5fd5254899651bce2751a09fe49c1e849ef223f225fb04722f5254be6bc1aa485f8af8e544fb6e54ffcdf8b54d4a0c44304ee5b3cc6feab4282d81a76c8b7 }


condition:
	$a0
}