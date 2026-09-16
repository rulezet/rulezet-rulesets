import "pe"
rule _with_added_PK_signature_
{
	meta:
		description = "with added 'PK' signature"
	strings:
		$0 = {C7 ?? ?? ?? ?? ?? 8C D8 05}
	condition:
		$0 at pe.entry_point
}