rule peninja
{
	meta:
		author = "PEiD"
		description = "PENinja -> +DZA Kracker/TNT!"
		group = "152"
		function = "0"
	strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
	condition:
		$a0
}