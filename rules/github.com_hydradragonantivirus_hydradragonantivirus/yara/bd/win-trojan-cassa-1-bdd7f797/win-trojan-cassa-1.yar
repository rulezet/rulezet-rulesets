rule Win_Trojan_Cassa_1
{
strings:
	$a0 = { 7b696628 }

	$a1 = { 292e676574657874656e73696f6e6e616d6528 }

	$a2 = { 2e6974656d2829292e746f75707065726361736528293d3d276a7327 }

	$a3 = { 2e6974656d2829213d }


condition:
	$a0 and $a1 and $a2 and $a3
}