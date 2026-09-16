rule Win_Trojan_Rusti_1
{
strings:
	$a0 = { 2ea39302e670e671b440ba0002b9e100cd21721733c933d2b80042cd21720cb440b90400ba92 }


condition:
	$a0
}