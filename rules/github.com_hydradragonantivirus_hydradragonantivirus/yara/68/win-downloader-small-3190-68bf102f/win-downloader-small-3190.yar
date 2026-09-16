rule Win_Downloader_Small_3190
{
strings:
	$a0 = { 076570bd79b13cc5fe8fe1b11845f77f234c6165d84f707aeebd7230e77d7628ed4f57859b28bfb8e5bc7632f45d542097c09729a3a2534bc5bc76b1134ce429edbc552ec3b6 }


condition:
	$a0
}