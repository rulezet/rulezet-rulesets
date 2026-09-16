import "pe"
rule honhaicert_goodcheck {
	strings:
		$honhai = "HON HAI"
	condition:
		$honhai and pe.version_info["LegalCopyright"] contains "Microsoft"
}