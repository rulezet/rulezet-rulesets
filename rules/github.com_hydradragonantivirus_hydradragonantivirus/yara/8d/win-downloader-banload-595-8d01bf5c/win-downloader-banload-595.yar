rule Win_Downloader_Banload_595
{
strings:
	$a0 = { 67358b79524ca9ca719c83ac6949f5dce4a59b19cd8bc88674d8b9c38f55318e20665bd6232d51b15a1cf36c4de64fe71502083d8a88b77e63fd82592ec1021f54e0aad3 }


condition:
	$a0
}