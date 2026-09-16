rule _Setup2Go_Installer_Stub_
{
	meta:
		description = "Setup2Go Installer Stub"
	strings:
		$0 = {5B 53 45 54 55 50 5F 49 4E 46 4F 5D 0D 0A 56 65 72}
	condition:
		$0
}