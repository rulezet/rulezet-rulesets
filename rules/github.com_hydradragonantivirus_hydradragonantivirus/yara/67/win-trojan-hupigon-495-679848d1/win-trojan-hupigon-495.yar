rule Win_Trojan_Hupigon_495
{
strings:
	$a0 = { e2e0cd7cfdb4c02c5a7cd00634d56f5f45f38191bfe8f0744c44b06179f2b8fc25a73b8000fdc7233c6d7237e528f6ffaf9527da8f0c6b91d1914482dcf0f698febf8fbe2713cf60854be2e962d7 }


condition:
	$a0
}