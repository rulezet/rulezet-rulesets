rule TTP_contains_XMR_address {
	meta:
		description = "Matches regex for Monero wallet addresses."
		last_modified = "2024-01-10"
        	author = "@petermstewart"
        	DaysofYara = "10/100"

	strings:
		$r1 = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ fullword ascii wide

	condition:
		filesize < 5MB and
		$r1
}