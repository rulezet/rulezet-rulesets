import "pe"
rule metasploit_service_starter
{
	meta:
		description = "This rule detects related metasploit service starters"
		author = "Adam Burt (adam_burt@symantec.com)"
	strings:
		$a1 = "StartServiceCtrlDispatcher"
		$a2 = "RegisterServiceCtrlHandle"
		$a3 = "CloseHandle"
		$a4 = "memset"
		$a5 = "rundll32.exe"
		$a6 = "msvcrt.dll"
	condition:
		pe.sections[3].name == ".bss"
		and pe.sections[3].virtual_size == 0x00000030
		and pe.sections[2].virtual_size == 0x0000001c
		and pe.sections[4].virtual_size == 0x00000224
		and all of them
}