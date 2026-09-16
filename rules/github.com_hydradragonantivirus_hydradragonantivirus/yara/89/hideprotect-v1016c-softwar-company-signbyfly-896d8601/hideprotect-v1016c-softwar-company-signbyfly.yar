import "pe"
rule _HideProtect_V1016C_SoftWar_Company____SignByfly_
{
	meta:
		description = "Hide&Protect V1.016C-> SoftWar Company   * Sign.By.fly"
	strings:
		$0 = {90 90 90 E9 D8}
	condition:
		$0 at pe.entry_point
}