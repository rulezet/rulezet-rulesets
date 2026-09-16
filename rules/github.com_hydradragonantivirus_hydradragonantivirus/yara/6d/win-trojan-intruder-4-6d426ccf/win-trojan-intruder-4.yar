rule Win_Trojan_Intruder_4
{
strings:
	$a0 = { 905825ff0190a38900b802009001068d00b91c0090ba87008b1efe0090b440cd2190a18d00 }


condition:
	$a0
}