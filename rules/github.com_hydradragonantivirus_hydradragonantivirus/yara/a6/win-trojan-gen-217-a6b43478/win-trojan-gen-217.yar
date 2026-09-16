rule Win_Trojan_Gen_217
{
strings:
	$a0 = { 57bf9d121e5768c01031c050509a9b085100bf44001e57bf44001e579a4309510052509a }


condition:
	$a0
}