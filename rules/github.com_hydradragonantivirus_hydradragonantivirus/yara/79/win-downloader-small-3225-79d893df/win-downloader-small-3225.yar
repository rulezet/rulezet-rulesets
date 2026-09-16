rule Win_Downloader_Small_3225
{
strings:
	$a0 = { 281124d636c4734948103f31cf2ee24529e4f48b12ed6291e9ee738edf1c71c4d6dc75dcdcee5471aa89bc4cd41d75c6c5fc57d4a66194dd920350bff41d754522ede7dddc1d }


condition:
	$a0
}