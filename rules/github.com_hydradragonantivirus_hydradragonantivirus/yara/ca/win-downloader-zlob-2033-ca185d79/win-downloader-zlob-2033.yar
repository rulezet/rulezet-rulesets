rule Win_Downloader_Zlob_2033
{
strings:
	$a0 = { a42a3ef664f6a52029fd851e4abdca6ff565f8a9accd019a7e087e3246b75a93ecc5ab5e5f3e6216201680bd350002ae016f }


condition:
	$a0
}