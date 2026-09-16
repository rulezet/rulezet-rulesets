rule Win_Downloader_Banload_972
{
strings:
	$a0 = { ebb4eec04278b12c2fe8427863bc099be6f7584d2bdb08a3b3bbcacece0923be4f86f0b242ced7860fc6d8db43534b0830628fcfad98aac52e243f8e512303a8e400be521f8ccbfcc22ed786896d }


condition:
	$a0
}