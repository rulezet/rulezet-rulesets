import "pe"
rule MSVC6
{
	meta:
		author="_pusher_"
		date = "2016-08"
		linker = "6.00"
	condition:
		pe.rich_signature.version(8447) and pe.rich_signature.version(7299) and pe.rich_signature.toolid(10) or
		pe.rich_signature.version(9782) and pe.rich_signature.version(7299) and pe.rich_signature.toolid(10) or
		pe.rich_signature.version(8168) and pe.rich_signature.version(1720) and pe.rich_signature.toolid(10) or
		pe.rich_signature.version(8168) and pe.rich_signature.version(7299) and pe.rich_signature.toolid(10) 
		and ((pe.linker_version.major == 6) and (pe.linker_version.minor == 0 )) or
		pe.rich_signature.version(8047) and pe.rich_signature.version(8034) and (pe.rich_signature.toolid(10) or pe.rich_signature.toolid(19)) or

		pe.rich_signature.version(8047) and pe.rich_signature.version(9044) and pe.rich_signature.toolid(10) and not pe.rich_signature.version(50727) or

		pe.rich_signature.version(4035) and pe.rich_signature.version(9044) and pe.rich_signature.toolid(95) and not pe.rich_signature.version(50727) or
		pe.rich_signature.version(8966) and pe.rich_signature.version(8047) and pe.rich_signature.toolid(10) or
		pe.rich_signature.version(8168) and pe.rich_signature.version(2179) and pe.rich_signature.toolid(10) or
		pe.rich_signature.version(8168) and pe.rich_signature.version(8034) and pe.rich_signature.toolid(11) or
		pe.rich_signature.version(8034) and pe.rich_signature.version(7299) and pe.rich_signature.toolid(19) or
		pe.rich_signature.version(8034) and pe.rich_signature.version(8966) and pe.rich_signature.toolid(19) or
		pe.rich_signature.version(9049) and pe.rich_signature.version(8966) and pe.rich_signature.toolid(19)
}