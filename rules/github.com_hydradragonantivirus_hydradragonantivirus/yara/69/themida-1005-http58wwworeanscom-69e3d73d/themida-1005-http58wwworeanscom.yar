import "pe"
rule _themida_1005__http58wwworeanscom_
{
	meta:
		description = "themida 1.0.0.5 -> http&#58;//www.oreans.com"
	strings:
		$0 = {B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03}
	condition:
		$0 at pe.entry_point
}