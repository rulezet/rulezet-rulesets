import "pe"
rule _UPX__wwwupxsourceforgenet_
{
	meta:
		description = "UPX -> www.upx.sourceforge.net"
	strings:
		$0 = {60 BE ?? ?? ?? 00 8D BE ?? ?? ?? FF}
	condition:
		$0 at pe.entry_point
}