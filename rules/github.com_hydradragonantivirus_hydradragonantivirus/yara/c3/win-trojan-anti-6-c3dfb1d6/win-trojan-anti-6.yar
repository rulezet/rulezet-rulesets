rule Win_Trojan_Anti_6
{
strings:
	$a0 = { 9703890db9b6038bd681ea9c03b440cd21722133c933d2b8420086e0cd217214b90300817cfe }


condition:
	$a0
}