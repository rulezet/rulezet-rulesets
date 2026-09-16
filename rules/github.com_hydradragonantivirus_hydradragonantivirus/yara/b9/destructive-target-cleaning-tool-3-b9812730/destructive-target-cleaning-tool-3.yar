rule Destructive_Target_Cleaning_Tool_3

{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:

		$S1_CMD_Arg = "/install" fullword
				
condition:

all of them
}