rule digest_edir_auth {
	meta:
		description = "Chinese Hacktool Set - file digest_edir_auth.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1dc349c91d890e3a1b897c2e8bb0ee1beeb34bd5"
	strings:
		$s0 = "Error reading Universal Password: %d = %s" fullword ascii
		$s1 = "read password for binddn from file secretfile" fullword ascii
		$s4 = "user search filter pattern. %%s = login" fullword ascii
		$s5 = "-D binddn -w bindpasswd or -D binddn -W secretfile options" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and all of them
}