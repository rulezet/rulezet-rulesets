import "pe"
rule _CorelDraw_CMX_Graphics_format_
{
	meta:
		description = "CorelDraw CMX Graphics format"
	strings:
		$0 = {52 49 46 46 ?? ?? ?? ?? 43 4D 58 31}
	condition:
		$0 at pe.entry_point
}