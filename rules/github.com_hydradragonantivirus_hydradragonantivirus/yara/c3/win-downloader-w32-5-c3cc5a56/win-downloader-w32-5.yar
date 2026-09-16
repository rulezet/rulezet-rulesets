rule Win_Downloader_W32_5
{
strings:
	$a0 = { b0654a5b491b7ab42bfac1df4f2edb04720253b0458a5ddbbf55d44abe1c607bb43c6d5b08127205bab029181ca6422a05eb2afdd53f8896b3740a89c848b7f6 }


condition:
	$a0
}