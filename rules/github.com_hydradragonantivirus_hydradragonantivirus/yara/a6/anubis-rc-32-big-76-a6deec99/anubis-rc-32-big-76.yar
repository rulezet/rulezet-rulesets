rule Anubis_RC__32_big_76_
{
strings:
	$a0 = { a7d3e671d0ac4d793ac991fc1e4754bd8ca57afb63b8ddd4e5b3c5bea9880ca239df29da2ba8cb4c4b22aa244170a6f95ae2b0367de433ff6020088b5eab7f787c2c57d2dc6d7e0d5394c328 }

condition:
	$a0
}