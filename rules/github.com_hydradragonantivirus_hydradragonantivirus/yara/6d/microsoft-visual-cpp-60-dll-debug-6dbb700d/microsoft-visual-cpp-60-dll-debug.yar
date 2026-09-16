rule _Microsoft_Visual_Cpp_60_DLL_Debug_
{
	meta:
		description = "Microsoft Visual C++ 6.0 DLL (Debug)"
	strings:
		$0 = {55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 ?? ?? 83}
	condition:
		$0
}