rule Win_Trojan_Bancos_979
{
strings:
	$a0 = { 2185ad55402c00d143f2d3ba58ed26f9040000d91c134dd4e115516a0ed504b8cada47c57efcfe0c752d838d68caf5f68782d8ae8f9f3230ec986e40b59ce0fcfc085ae69a5e4f03b37ec8b1a6871eff8ce6 }


condition:
	$a0
}