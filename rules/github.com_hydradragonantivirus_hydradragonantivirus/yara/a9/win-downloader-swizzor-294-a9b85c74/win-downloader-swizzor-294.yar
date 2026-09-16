rule Win_Downloader_Swizzor_294
{
strings:
	$a0 = { 73bafcdc3474a6ada50ec7531d618625924d12c613314b36579c665b5a1fce853aa6a167e28d59e00a461b4730c334ed6ac471afa603a38c48f5bcd9a924c0388bc0e3d4a4ff98cd11312f11 }


condition:
	$a0
}