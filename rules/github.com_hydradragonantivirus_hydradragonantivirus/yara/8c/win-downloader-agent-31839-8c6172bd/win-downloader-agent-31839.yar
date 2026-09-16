rule Win_Downloader_Agent_31839
{
strings:
	$a0 = { a5ea79ab51f6fa7c418f0a4fb889f9ff88208e1d136fe0e84d967fc3e4f7252bdfc74b8ef49859d2fc58556dfa379df3825f838aa406b8cb628702adf880cb8c24fdd9a8bf9993d662fa06 }


condition:
	$a0
}