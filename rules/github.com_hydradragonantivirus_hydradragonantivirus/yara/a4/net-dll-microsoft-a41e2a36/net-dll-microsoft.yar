rule _NET_DLL__Microsoft_
{
	meta:
		description = ".NET DLL -> Microsoft"
	strings:
		$0 = {00 00 00 00 00 00 00 00 5F 43 6F 72 44 6C 6C 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C 00 00 ?? 00 00 FF 25}
	condition:
		$0
}