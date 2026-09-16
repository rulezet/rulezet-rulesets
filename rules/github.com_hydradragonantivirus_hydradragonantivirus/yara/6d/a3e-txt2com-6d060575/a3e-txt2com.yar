import "pe"
rule _A3E_TXT2COM_
{
	meta:
		description = "A3E (TXT2COM)"
	strings:
		$0 = {1E 33 C0 50 BE ?? ?? 81 C6 ?? ?? B8 ?? ?? 8E C0 BF ?? ?? B9 ?? ?? F3 A5 CB}
	condition:
		$0 at pe.entry_point
}