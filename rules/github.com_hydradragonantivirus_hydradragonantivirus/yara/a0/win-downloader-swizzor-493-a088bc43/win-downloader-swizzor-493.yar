rule Win_Downloader_Swizzor_493
{
strings:
	$a0 = { 5d8af3377d62c38b3e74e8a6b2f29b5207e4a2a56f932d9ff7bc140b39bca1cd0f68d2c0a40caa08b6e0514b200040801c71275aeee36281eca2e0c1e4f1724e4cf5dcbb8462f6b694f1ea61b7e6 }


condition:
	$a0
}