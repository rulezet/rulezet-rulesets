rule Win_Trojan_Peed_304
{
strings:
	$a0 = { 404752fc5df7d5fff23bc85ef7df81ea863dd200fff27603c1d1843ace46d65f3ccff7da89e9bb74f9e6530f8613000000fff53af5c1d60684cdf55d33d6f7d6 }


condition:
	$a0
}