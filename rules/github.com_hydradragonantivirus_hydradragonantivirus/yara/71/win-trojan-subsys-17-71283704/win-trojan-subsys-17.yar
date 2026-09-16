rule Win_Trojan_Subsys_17
{
strings:
	$a0 = { 2b6b56df5b17e4b4439a7359142ee853a9f64bf22d38f10fad05ad04d193606be3c2dc932680ce2df78811b320ae2a7b }


condition:
	$a0
}