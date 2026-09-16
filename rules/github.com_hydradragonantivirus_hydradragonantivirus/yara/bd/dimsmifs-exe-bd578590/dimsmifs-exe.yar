rule dimsmifs_exe {
	meta:
		description = "Auto-generated rule - file dimsmifs.exe.malware"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-11-14"
		hash1 = "a6830427d8b818ac690af6f3a6fa974bc286d9e5861550279267280594284f5d"
	strings:
		$s1 = "G:\\DOCS!!!\\MyProg\\FREELANCE\\CURRENT\\Krypton\\Krypton_15.0\\Bin\\StubNew.pdb" fullword ascii 
		$s2 = "LoaderPE: CreateProcess error:0x%X" fullword ascii 
		$s3 = "zero.exe" fullword ascii 
		$s4 = "RtlComputeCrc32=%d, PostCRC32=%d" fullword ascii 
		$s5 = "GetProcAddressNt: %s - OK" fullword ascii 
		$s6 = "FromBase64Crypto: PostCRC32 - OK" fullword ascii 
		$s7 = "GetProcAddressNt#%d: %s: %s" fullword ascii 
		$s8 = "LoaderPE: Error CRC GO Exit1" fullword ascii 
		$s9 = "FromBase64Crypto: MemAllOk: %d, fun 0x%X" fullword ascii 
		$s10 = "8\"x:\"5.)|z~</" fullword ascii 
		$s11 = "DR0 = 0x%X,DR1 = 0x%X,DR2 = 0x%X,DR3 = 0x%X,DR6 = 0x%X,DR7 = 0x%X" fullword ascii 
		$s12 = "FromBase64Crypto: B64 error = 0x%p" fullword ascii 
		$s13 = "kgwnmqghbpfphjij" fullword ascii 
		$s14 = "oxgxteijvinoawfpo" fullword ascii 
		$s15 = "dwwKey from map = 0x%X" fullword ascii 
		$s16 = "KEY = 0x%X, Len = %d" fullword ascii 
		$s17 = "on_tls_callback2: Main FILE IS a DLL" fullword ascii 
		$s18 = "blhvfpadnwxhseo" fullword ascii 
		$s19 = "wtgtgbvdrclboj" fullword ascii 
		$s20 = "wpjhgmtboviobx" fullword ascii 
	condition:
		( uint16(0) == 0x5a4d and filesize < 700KB and ( 10 of ($s*) ) ) or ( all of them )
}