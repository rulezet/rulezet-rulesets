import "pe"
rule _Microsoft_Visual_Studio_NET_
{
	meta:
		description = "Microsoft Visual Studio .NET"
	strings:
		$0 = {FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}