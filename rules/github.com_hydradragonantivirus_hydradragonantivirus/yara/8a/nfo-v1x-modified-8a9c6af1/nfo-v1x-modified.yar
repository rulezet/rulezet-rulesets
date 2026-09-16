import "pe"
rule _NFO_v1x_modified_
{
	meta:
		description = "NFO v1.x modified"
	strings:
		$0 = {EB 01 9A E8 3D ?? ?? ?? EB 01 9A E8 EB 01 ?? ?? EB 01 9A E8 2C 04 ?? ?? EB}
	condition:
		$0 at pe.entry_point
}