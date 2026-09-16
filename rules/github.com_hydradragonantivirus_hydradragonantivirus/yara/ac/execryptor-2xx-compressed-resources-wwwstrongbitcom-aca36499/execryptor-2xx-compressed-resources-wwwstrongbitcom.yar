import "pe"
rule _EXECryptor_2xx_compressed_resources__wwwstrongbitcom_
{
	meta:
		description = "EXECryptor 2.xx (compressed resources) -> www.strongbit.com"
	strings:
		$0 = {56 57 53 31 DB 89 C6 89 D7 0F B6 06 89 C2 83 E0 1F C1 EA 05 74 2D 4A 74 15 8D 5C 13 02 46 C1 E0 08 89 FA 0F B6 0E 46 29 CA 4A 29 C2 EB 32 C1 E3 05 8D 5C 03 04 46 89 FA 0F B7 0E 29 CA 4A 83 C6 02 EB 1D C1 E3 04 46 89 C1 83 E1 0F 01 CB C1 E8 05 73 07 43 89}
	condition:
		$0 at pe.entry_point
}