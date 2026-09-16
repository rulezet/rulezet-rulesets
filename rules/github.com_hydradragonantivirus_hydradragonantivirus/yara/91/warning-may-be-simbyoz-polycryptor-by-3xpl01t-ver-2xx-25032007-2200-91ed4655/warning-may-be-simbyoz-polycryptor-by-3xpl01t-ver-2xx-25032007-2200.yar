import "pe"
rule _Warning_may_be_SimbyOZ_polycryptor_by_3xpl01t_ver_2xx_25032007_2200_
{
	meta:
		description = "Warning! may be SimbyOZ polycryptor by 3xpl01t ver 2.xx (25.03.2007 22:00)"
	strings:
		$0 = {57 57 8D 7C 24 04 50 B8 00 D0 17 13 AB 58 5F C3 00 00}
	condition:
		$0 at pe.entry_point
}