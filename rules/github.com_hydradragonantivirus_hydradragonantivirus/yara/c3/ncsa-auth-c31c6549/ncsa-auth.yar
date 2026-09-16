rule ncsa_auth {
	meta:
		description = "Chinese Hacktool Set - file ncsa_auth.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d87c984107adc3921720f4c76608dc6ed68b2d84"
	strings:
		$s0 = "Usage: ncsa_auth <passwordfile>" fullword ascii
		$s1 = "ERR Wrong password" fullword ascii
		$s2 = "ERR No such user" fullword ascii
		$s6 = "ncsa_auth: cannot create hash table" fullword ascii
		$s20 = "(%d) %s" fullword ascii 
	condition:
		uint16(0) == 0x5a4d and filesize < 440KB and all of them
}