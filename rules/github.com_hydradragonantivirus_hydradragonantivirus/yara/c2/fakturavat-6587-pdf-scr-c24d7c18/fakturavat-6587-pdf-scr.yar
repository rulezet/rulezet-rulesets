rule FakturaVAT_6587_pdf_scr {
	meta:
		description = "Auto-generated rule - file FakturaVAT_6587.pdf.scr.txt"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-11-14"
		hash1 = "031d175a52280e5da95a0265d7156ed67d63d5c9d79e4ea972586045e44dec11"
	strings:
		$s1 = "$$$$$$$$$$$$,,,,,,4444444<<<<<<DDDDDDDLLLLLLTTTTTT\\\\\\\\\\\\\\ddddddlllllltttttt||||||" fullword ascii 
		$s2 = "$$$$$$$$$$$$,,,,,,,444444<<<<<<DDDDDDDLLLLLLTTTTLT\\\\\\\\\\\\dddddddlllllltttttt||||||" fullword ascii 
		$s3 = "$$$$$$$$$$$$,,,,,,,444444<<<<<<DDDDDDDLLLLLLTTTTTT\\\\\\\\\\\\dddddddlllllltttttt||||||" fullword ascii 
		$s4 = "$$$$$$$$$$$$,,,,,,4444444<<<<<<DDDDDDDLLLLLLTTTTLT\\\\\\\\\\\\dddddddlllllltttttt||||||" fullword ascii 
		$s5 = "$$$$$$$$$$$$,,,,,,4444444<<<<<<DDDDDDDLLLLLLTTTTTT\\\\\\\\\\\\dddddddlllllltttttt||||||" fullword ascii 
		$s6 = "$$$$$$$$$$$$,,,,,,4444444<<<<<<DDDDDDDLLLLLLTTTTLT\\\\\\\\T\\dddddddlllllltttttt||||||" fullword ascii 
		$s7 = "$$$$$$$$$$$$,,,,,,4444444<<<<<<DDDDDDDLLLLLLTTTTTT\\\\\\\\T\\dddddddlllllltttttt||||||" fullword ascii 
		$s8 = "$$$$$$$$$$$$,,,,,,4444444<<<<<<DDDDDDDLLLLLLTTTTLT\\\\\\\\T\\\\ddddddlllllltttttt||||||" fullword ascii 
		$s9 = ".FTP()" fullword ascii 
		$s10 = "L@CMainFrame" fullword ascii 
		$s11 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii 
		$s12 = "Laplacian" fullword wide 
		$s13 = "Prewitt" fullword wide 
		$s14 = "?????0-360??????" fullword wide 
	condition:
		( uint16(0) == 0x5a4d and filesize < 500KB and ( 10 of ($s*) ) ) or ( all of them )
}