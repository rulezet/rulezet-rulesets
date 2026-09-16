rule Win_Downloader_Swizzor_268
{
strings:
	$a0 = { 39ad2dd27d1024665150fcddd8911f6b5f0782b2ba540e1bb17cf5c574f45faad8cf5b11a150b780edc8ac8935146d3fe6679e2b0c590560853d7454b627bc3271079fde2c53d7f28f6f2d3c }


condition:
	$a0
}