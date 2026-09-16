rule Win_Downloader_Agent_32871
{
strings:
	$a0 = { 1c7fb0fbdbae5eb9db4f746fc6a670bfc3f490da71e4ba56fde7e7b5ba5e8da3e4ed2d0b99753736cf436fea30cda46c4f2ebeea8f533a5fa6d60dbbd5f2 }


condition:
	$a0
}