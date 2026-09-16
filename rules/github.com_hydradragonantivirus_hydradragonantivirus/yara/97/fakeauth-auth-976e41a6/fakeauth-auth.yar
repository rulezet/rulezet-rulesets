rule fakeauth_auth {
	meta:
		description = "Chinese Hacktool Set - file fakeauth_auth.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4d6311159e10ffbb904059ccfda70fde2fee1f7e"
	strings:
		$s0 = "sending 'NA invalid credentials, user=%s' to squid" fullword ascii
		$s11 = "BH wrong packet type! user=%s" fullword ascii
		$s16 = "fakeauth_auth[%ld]: " fullword ascii
		$s20 = "sending 'TT %s' to squid" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 260KB and all of them
}