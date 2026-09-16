rule viewweb {
	strings:
		$dllstring = "viewweb.dll\x00DllCmd\x00"

	condition:
		uint16be(0) == 0x4d5a and $dllstring
}