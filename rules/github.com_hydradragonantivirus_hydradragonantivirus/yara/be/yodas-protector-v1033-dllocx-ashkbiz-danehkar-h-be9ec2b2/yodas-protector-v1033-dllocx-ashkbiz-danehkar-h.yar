rule _yodas_Protector_v1033_dllocx__Ashkbiz_Danehkar_h_
{
	meta:
		description = "yoda's Protector v1.03.3 (.dll,.ocx) -> Ashkbiz Danehkar (h)"
	strings:
		$0 = {60}
	condition:
		$0
}