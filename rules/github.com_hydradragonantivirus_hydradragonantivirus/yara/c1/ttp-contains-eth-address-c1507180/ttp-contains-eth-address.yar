rule TTP_contains_ETH_address {
	meta:
		description = "Matches regex for Ethereum wallet addresses."
		last_modified = "2024-01-09"
        	author = "@petermstewart"
        	DaysofYara = "9/100"

	strings:
		$r1 = /0x[a-fA-F0-9]{40}/ fullword ascii wide

	condition:
		filesize < 5MB and
		$r1
}