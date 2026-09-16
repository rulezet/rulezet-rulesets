rule Win_Trojan_Rajaat_7
{
strings:
	$a0 = { 8e038f066b03ff368c038f066d03ff3686038f066f03 }


condition:
	$a0
}