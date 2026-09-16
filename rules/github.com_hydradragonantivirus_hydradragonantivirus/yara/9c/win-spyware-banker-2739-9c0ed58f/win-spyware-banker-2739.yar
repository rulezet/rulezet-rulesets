rule Win_Spyware_Banker_2739
{
strings:
	$a0 = { 09fc233eb57bfe5fb9a925a7aa0162a45f06006266fdccdbb155bd5999244d3bbbf9bb681130ffa0a598160cbc0c7b81ecce95bde4d4abefbfe0fe8f8e90ecf9a859375f97d908c8291452c7264b }


condition:
	$a0
}