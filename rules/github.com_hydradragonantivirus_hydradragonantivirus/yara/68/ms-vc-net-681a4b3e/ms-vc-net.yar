rule ms_vc_net
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C# / Basic .NET"
		group = "115"
		function = "0"
	strings:
		$a0 = { FF 25 00 20 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$a0
}