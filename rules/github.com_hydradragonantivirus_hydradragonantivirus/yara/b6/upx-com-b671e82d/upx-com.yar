import "pe"
rule _UPX_com_
{
	meta:
		description = "UPX [com"
	strings:
		$0 = {B9 ?? ?? BE ?? ?? BF C0 FF FD}
	condition:
		$0 at pe.entry_point
}